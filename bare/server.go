package bare

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	maxHeaderValue = 3072
)

type BareError struct {
	Status  int    `json:"status"`
	Code    string `json:"code"`
	ID      string `json:"id"`
	Message string `json:"message,omitempty"`
	Stack   string `json:"stack,omitempty"`
}

func (e *BareError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

type BareServer struct {
	directory    string
	routes       map[string]RouteCallback
	socketRoutes map[string]SocketRouteCallback
	versions     []string
	closed       bool
	options      *Options
	wss          *websocket.Upgrader
	db           *JSONDatabaseAdapter
}

type Options struct {
	LogErrors    bool
	FilterRemote func(*url.URL) error
	Lookup       func(hostname string, service string, hints ...net.IPAddr) (addrs []net.IPAddr, err error)
	LocalAddress string
	Family       int
	Maintainer   *BareMaintainer
	httpAgent    *http.Transport
	httpsAgent   *http.Transport
}

type RouteCallback func(request *BareRequest, response http.ResponseWriter, options *Options) (*Response, error)

type SocketRouteCallback func(request *BareRequest, conn *websocket.Conn, options *Options) error

type BareRequest struct {
	*http.Request
	Native *http.Request
}

type Response struct {
	StatusCode int
	Status     string
	Headers    http.Header
	Body       io.ReadCloser
}

func (r *Response) Write(w http.ResponseWriter) (err error) {
	for key, values := range r.Headers {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	defer r.Body.Close()
	w.WriteHeader(r.StatusCode)
	if r.Body != nil {
		_, err = io.Copy(w, r.Body)
		return err
	}
	return nil
}

type BareMaintainer struct {
	Email   string `json:"email,omitempty"`
	Website string `json:"website,omitempty"`
}

type BareProject struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Email       string `json:"email,omitempty"`
	Website     string `json:"website,omitempty"`
	Repository  string `json:"repository,omitempty"`
	Version     string `json:"version,omitempty"`
}

type BareLanguage string

const (
	LanguageNodeJS        BareLanguage = "NodeJS"
	LanguageServiceWorker BareLanguage = "ServiceWorker"
	LanguageDeno          BareLanguage = "Deno"
	LanguageJava          BareLanguage = "Java"
	LanguagePHP           BareLanguage = "PHP"
	LanguageRust          BareLanguage = "Rust"
	LanguageC             BareLanguage = "C"
	LanguageCPlusPlus     BareLanguage = "C++"
	LanguageCSharp        BareLanguage = "C#"
	LanguageRuby          BareLanguage = "Ruby"
	LanguageGo            BareLanguage = "Go"
	LanguageCrystal       BareLanguage = "Crystal"
	LanguageShell         BareLanguage = "Shell"
)

type BareManifest struct {
	Maintainer  *BareMaintainer `json:"maintainer,omitempty"`
	Project     *BareProject    `json:"project,omitempty"`
	Versions    []string        `json:"versions"`
	Language    BareLanguage    `json:"language"`
	MemoryUsage float64         `json:"memoryUsage,omitempty"`
}

func NewBareServer(directory string, options *Options) *BareServer {
	if options.LogErrors == false {
		options.LogErrors = false
	}

	if options.FilterRemote == nil {
		options.FilterRemote = func(remote *url.URL) error {
			if isValidIP(remote.Hostname()) && parseIP(remote.Hostname()).IsGlobalUnicast() == false {
				return errors.New("forbidden IP")
			}
			return nil
		}
	}

	if options.Lookup == nil {
		options.Lookup = func(hostname string, service string, hints ...net.IPAddr) (addrs []net.IPAddr, err error) {
			ips, err := net.LookupIP(hostname)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				addrs = append(addrs, net.IPAddr{IP: ip})
			}
			return addrs, nil
		}
	}

	if options.httpAgent == nil {
		options.httpAgent = &http.Transport{
			DialContext: (&net.Dialer{
				LocalAddr: getLocalAddr(options.LocalAddress, options.Family),
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			// ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}

	if options.httpsAgent == nil {
		options.httpsAgent = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: (&net.Dialer{
				LocalAddr: getLocalAddr(options.LocalAddress, options.Family),
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			// ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}

	server := &BareServer{
		directory:    directory,
		routes:       make(map[string]RouteCallback),
		socketRoutes: make(map[string]SocketRouteCallback),
		versions:     make([]string, 0),
		options:      options,
		wss: &websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		db: NewJSONDatabaseAdapter(NewMemoryDatabase()),
	}

	return server
}

func (s *BareServer) Close() {
	s.closed = true
}

func (s *BareServer) DB() *JSONDatabaseAdapter {
	return s.db
}

func (s *BareServer) Register(version string) {
	s.versions = append(s.versions, version)
}

func (s *BareServer) ShouldRoute(request *http.Request) bool {
	return !s.closed && strings.HasPrefix(request.URL.Path, s.directory)
}

func (s *BareServer) RouteUpgrade(w http.ResponseWriter, r *http.Request, conn *websocket.Conn) {
	request := &BareRequest{
		Request: r,
		Native:  r,
	}

	service := strings.TrimPrefix(r.URL.Path, s.directory)

	if handler, ok := s.socketRoutes[service]; ok {
		if err := handler(request, conn, s.options); err != nil {
			if s.options.LogErrors {
				fmt.Fprintf(os.Stderr, "Error in socket handler: %s\n", err)
			}
			conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseInternalServerErr, err.Error()), time.Now().Add(time.Second*10))
			conn.Close()
			return
		}
	} else {
		conn.Close()
	}
}

func (s *BareServer) RouteRequest(w http.ResponseWriter, r *http.Request) {
	request := &BareRequest{
		Request: r,
		Native:  r,
	}

	service := strings.TrimPrefix(r.URL.Path, s.directory)
	var response *Response
	var err error

	defer func() {
		if err != nil {
			if s.options.LogErrors {
				fmt.Fprintf(os.Stderr, "Error handling request: %s\n", err)
			}

			if httpErr, ok := err.(error); ok {
				if strings.HasPrefix(httpErr.Error(), "404") {
					http.Error(w, httpErr.Error(), http.StatusNotFound)
				} else {
					http.Error(w, httpErr.Error(), http.StatusInternalServerError)
				}
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}

			return
		}
		if response != nil {
			if err := response.Write(w); err != nil {
				if s.options.LogErrors {
					fmt.Fprintf(os.Stderr, "Error writing response: %s\n", err)
				}
			}
		}
	}()

	if r.Method == http.MethodOptions {
		response = &Response{
			StatusCode: http.StatusOK,
			Headers:    make(http.Header),
		}
	} else if service == "/" {
		response = &Response{
			StatusCode: http.StatusOK,
			Headers:    make(http.Header),
			Body:       s.getInstanceInfo(),
		}
	} else if handler, ok := s.routes[service]; ok {
		response, err = handler(request, w, s.options)
	} else {
		err = createHttpError(http.StatusNotFound, "Not Found")
	}
}

func (s *BareServer) getInstanceInfo() io.ReadCloser {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	info := BareManifest{
		Versions:    s.versions,
		Language:    LanguageGo,
		MemoryUsage: float64(memStats.HeapAlloc) / 1024 / 1024,
		Maintainer:  s.options.Maintainer,
		Project: &BareProject{
			Name:        "bare-server-go",
			Description: "Bare server implementation in Go",
			Repository:  "https://github.com/genericness/bare-server-go",
			Version:     "0.1.0",
		},
	}

	jsonData, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		panic(err)
	}

	return io.NopCloser(bytes.NewReader(jsonData))
}

func (s *BareServer) Handle(pattern string, handler RouteCallback) {
	s.routes[pattern] = handler
}

func (s *BareServer) HandleSocket(pattern string, handler SocketRouteCallback) {
	s.socketRoutes[pattern] = handler
}

func (s *BareServer) Start(addr string) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if s.ShouldRoute(r) {
			if websocket.IsWebSocketUpgrade(r) {
				conn, err := s.wss.Upgrade(w, r, nil)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error upgrading to websocket: %s\n", err)
					return
				}
				s.RouteUpgrade(w, r, conn)
			} else {
				s.RouteRequest(w, r)
			}
		} else {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "Not found")
		}
	})

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Error starting server: %s\n", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop

	fmt.Println("Shutting down server...")
	if err := server.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Error shutting down server: %s\n", err)
	}

	return nil
}

func SplitHeaders(headers http.Header) http.Header {
	output := make(http.Header)
	for key, values := range headers {
		output[key] = values
	}

	if values, ok := headers["X-Bare-Headers"]; ok {
		value := strings.Join(values, ", ")
		if len(value) > maxHeaderValue {
			delete(output, "X-Bare-Headers")
			split := 0
			for i := 0; i < len(value); i += maxHeaderValue {
				part := value[i:min(i+maxHeaderValue, len(value))]
				id := strconv.Itoa(split)
				output.Add(fmt.Sprintf("X-Bare-Headers-%s", id), ";"+part)
				split++
			}
		}
	}

	return output
}

func JoinHeaders(headers http.Header) http.Header {
	output := make(http.Header)
	for key, values := range headers {
		output[key] = values
	}

	prefix := "x-bare-headers-"
	if _, ok := headers[prefix+"0"]; ok {
		var join []string
		for header := range headers {
			if strings.HasPrefix(strings.ToLower(header), prefix) {
				value := headers.Get(header)
				if !strings.HasPrefix(value, ";") {
					panic(&BareError{400, "INVALID_BARE_HEADER", fmt.Sprintf("request.headers.%s", header), "Value didn't begin with semi-colon.", ""})
				}
				join = append(join, value[1:])
				delete(output, header)
			}
		}
		output.Set("x-bare-headers", strings.Join(join, ""))
	}

	return output
}

func RandomHex(byteLength int) string {
	bytes := make([]byte, byteLength)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes)
}

func outgoingError(err error) error {
	if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() {
			return &BareError{500, "CONNECTION_TIMEOUT", "response", "The response timed out.", ""}
		}
		if opErr, ok := netErr.(*net.OpError); ok {
			switch opErr.Err.Error() {
			case "no such host":
				return &BareError{500, "HOST_NOT_FOUND", "request", "The specified host could not be resolved.", ""}
			case "connection refused":
				return &BareError{500, "CONNECTION_REFUSED", "response", "The remote rejected the request.", ""}
			case "connection reset by peer":
				return &BareError{500, "CONNECTION_RESET", "response", "The request was forcibly closed.", ""}
			}
		}
	}
	return err
}

func BareFetch(request *BareRequest, requestHeaders http.Header, remote *url.URL, options *Options) (*http.Response, error) {
	if options.FilterRemote != nil {
		if err := options.FilterRemote(remote); err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(request.Method, remote.String(), request.Body)
	if err != nil {
		return nil, err
	}

	req.Header = requestHeaders

	var client *http.Client
	if remote.Scheme == "https" {
		if options.httpsAgent != nil {
			client = &http.Client{Transport: options.httpsAgent}
		} else {
			client = &http.Client{}
		}
	} else {
		if options.httpAgent != nil {
			client = &http.Client{Transport: options.httpAgent}
		} else {
			client = &http.Client{}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, outgoingError(err)
	}

	return resp, nil
}

func BareUpgradeFetch(request *BareRequest, requestHeaders http.Header, remote *url.URL, options *Options) (*http.Response, *tls.Conn, error) {
	if options.FilterRemote != nil {
		if err := options.FilterRemote(remote); err != nil {
			return nil, nil, err
		}
	}

	dialer := &net.Dialer{
		LocalAddr: getLocalAddr(options.LocalAddress, options.Family),
		Timeout:   12 * time.Second,
	}

	var conn net.Conn
	var err error

	if remote.Scheme == "wss" {
		conn, err = tls.DialWithDialer(dialer, "tcp", remote.Host, &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = dialer.Dial("tcp", remote.Host)
	}

	if err != nil {
		return nil, nil, outgoingError(err)
	}

	req := &http.Request{
		Method:     request.Method,
		URL:        remote,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     requestHeaders,
		Body:       request.Body,
		Host:       remote.Host,
	}

	if err := req.Write(conn); err != nil {
		return nil, nil, err
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, nil, err
	}

	return resp, conn.(*tls.Conn), nil
}

func WebSocketFetch(request *BareRequest, requestHeaders http.Header, remote *url.URL, protocols []string, options *Options) (*http.Response, *websocket.Conn, *http.Request, error) {
	if options.FilterRemote != nil {
		if err := options.FilterRemote(remote); err != nil {
			return nil, nil, nil, err
		}
	}

	dialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 12 * time.Second,
		NetDialContext:   (&net.Dialer{LocalAddr: getLocalAddr(options.LocalAddress, options.Family)}).DialContext,
		Subprotocols:     protocols,
	}

	conn, resp, err := dialer.Dial(remote.String(), requestHeaders)
	if err != nil {
		return nil, nil, nil, outgoingError(err)
	}

	return resp, conn, resp.Request, nil
}

func RemoteToURL(remote map[string]string) (*url.URL, error) {
	port := remote["port"]
	if port == "" {
		if remote["protocol"] == "http:" {
			port = "80"
		} else if remote["protocol"] == "https:" {
			port = "443"
		}
	}

	urlStr := fmt.Sprintf("%s//%s:%s%s", remote["protocol"], remote["host"], port, remote["path"])
	return url.Parse(urlStr)
}

func ObjectFromRawHeaders(raw []string) http.Header {
	headers := make(http.Header)
	for i := 0; i < len(raw); i += 2 {
		key := raw[i]
		value := raw[i+1]
		headers.Add(key, value)
	}
	return headers
}

func RawHeaderNames(raw http.Header) []string {
	var names []string
	for name := range raw {
		names = append(names, name)
	}
	return names
}

func MapHeadersFromArray(from []string, to http.Header) http.Header {
	for _, header := range from {
		if values, ok := to[strings.ToLower(header)]; ok {
			to[header] = values
			delete(to, strings.ToLower(header))
		}
	}
	return to
}

func FlattenHeader(values []string) string {
	return strings.Join(values, ", ")
}

func JSON(w http.ResponseWriter, statusCode int, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	return json.NewEncoder(w).Encode(data)
}

type SocketClientToServer struct {
	Type           string      `json:"type"`
	Remote         string      `json:"remote"`
	Protocols      []string    `json:"protocols"`
	Headers        http.Header `json:"headers"`
	ForwardHeaders []string    `json:"forwardHeaders"`
}

type SocketServerToClient struct {
	Type       string   `json:"type"`
	Protocol   string   `json:"protocol"`
	SetCookies []string `json:"setCookies"`
}

type Database interface {
	Get(key string) (string, error)
	Set(key string, value string, expiration time.Duration) error
	Delete(key string) error
}

type MemoryDatabase struct {
	data        map[string]string
	expirations map[string]time.Time
	mutex       sync.RWMutex
}

func NewMemoryDatabase() *MemoryDatabase {
	db := &MemoryDatabase{
		data:        make(map[string]string),
		expirations: make(map[string]time.Time),
		mutex:       sync.RWMutex{},
	}
	go db.cleanupExpiredKeys()
	return db
}

func (db *MemoryDatabase) Get(key string) (string, error) {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	if expiration, ok := db.expirations[key]; ok {
		if time.Now().After(expiration) {
			delete(db.data, key)
			delete(db.expirations, key)
			return "", nil
		}
	}

	value, ok := db.data[key]
	if !ok {
		return "", nil
	}
	return value, nil
}

func (db *MemoryDatabase) Set(key string, value string, expiration time.Duration) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	db.data[key] = value
	db.expirations[key] = time.Now().Add(expiration)
	return nil
}

func (db *MemoryDatabase) Delete(key string) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	delete(db.data, key)
	delete(db.expirations, key)
	return nil
}

func (db *MemoryDatabase) cleanupExpiredKeys() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		<-ticker.C

		db.mutex.Lock()
		for key, expiration := range db.expirations {
			if time.Now().After(expiration) {
				delete(db.data, key)
				delete(db.expirations, key)
			}
		}
		db.mutex.Unlock()
	}
}

type JSONDatabaseAdapter struct {
	db Database
}

func NewJSONDatabaseAdapter(db Database) *JSONDatabaseAdapter {
	return &JSONDatabaseAdapter{db: db}
}

func (jda *JSONDatabaseAdapter) Get(key string) (string, error) {
	return jda.db.Get(key)
}

func (jda *JSONDatabaseAdapter) Set(key string, value string, expiration time.Duration) error {
	return jda.db.Set(key, value, expiration)
}

func (jda *JSONDatabaseAdapter) Delete(key string) error {
	return jda.db.Delete(key)
}

func DecodeProtocol(protocol string) (string, error) {
	return url.PathUnescape(protocol)
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func parseIP(ip string) net.IP {
	return net.ParseIP(ip)
}

func getLocalAddr(localAddress string, family int) net.Addr {
	if localAddress != "" {
		if ip := net.ParseIP(localAddress); ip != nil {
			if family == 0 || ip.To4() != nil && family == 4 || ip.To16() != nil && family == 6 {
				return &net.TCPAddr{IP: ip}
			}
		}
	}
	return nil
}

func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func ContainsInt(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func createHttpError(statusCode int, message string) error {
	return fmt.Errorf("%d %s", statusCode, message)
}
