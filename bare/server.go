package bare

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/gorilla/websocket"
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
	routes       map[string]RouteCallback
	socketRoutes map[string]SocketRouteCallback
	versions     []string
	closed       bool
	options      *Options
	wss          *websocket.Upgrader
	db           *JSONDatabaseAdapter
}

type Options struct {
	FilterRemote   func(*url.URL) error
	Lookup         func(hostname string, service string, hints ...net.IPAddr) (addrs []net.IPAddr, err error)
	Maintainer     *BareMaintainer
	httpAgent      *http.Transport
	httpsAgent     *http.Transport
	LocalAddress   string
	Family         int
	LogErrors      bool
	APIPath        string
	AddrHttp       string
	AddrHttps      string
	StaticDir      string
	MaintainerFile string
	CertFile       string
	KeyFile        string
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

	w.Header().Set("x-robots-tag", "noindex")
	w.Header().Set("access-control-allow-headers", "*")
	w.Header().Set("access-control-allow-origin", "*")
	w.Header().Set("access-control-allow-methods", "*")
	w.Header().Set("access-control-expose-headers", "*")
	// don"t fetch preflight on every request...
	// instead, fetch preflight every 10 minutes
	w.Header().Set("access-control-max-age", "7200")

	defer r.Body.Close()
	w.WriteHeader(r.StatusCode)
	if r.Body != nil {
		_, err = io.Copy(w, r.Body)
		return err
	} else {
		w.WriteHeader(http.StatusNoContent)
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

func NewBareServer(options *Options) *BareServer {
	if !strings.HasPrefix(options.APIPath, "/") || !strings.HasSuffix(options.APIPath, "/") {
		log.Fatal("Directory must start and end with /")
		return nil
	}

	if options.FilterRemote == nil {
		options.FilterRemote = func(remote *url.URL) error {
			if isValidIP(remote.Hostname()) && !parseIP(remote.Hostname()).IsGlobalUnicast() {
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
			DisableKeepAlives:     false,
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
				// KeepAliveConfig: net.KeepAliveConfig{Enable: true},
				DualStack: true,
			}).DialContext,
			// ForceAttemptHTTP2:     true,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}

	server := &BareServer{
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
	return !s.closed && strings.HasPrefix(request.URL.Path, s.options.APIPath)
}

func (s *BareServer) RouteUpgrade(w http.ResponseWriter, r *http.Request, conn *websocket.Conn) {
	request := &BareRequest{
		Request: r,
		Native:  r,
	}

	service := strings.TrimPrefix(r.URL.Path, s.options.APIPath)

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

	service := strings.TrimPrefix(r.URL.Path, s.options.APIPath[:len(s.options.APIPath)-1])
	var response *Response
	var err error

	defer func() {
		if err != nil {
			if s.options.LogErrors {
				fmt.Fprintf(os.Stderr, "Error handling request: %s\n", err)
			}

			if strings.HasPrefix(err.Error(), "404") {
				http.Error(w, err.Error(), http.StatusNotFound)
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
	} else {
		if service == "/" {
			// 获取manifest信息
			response = &Response{
				StatusCode: http.StatusOK,
				Headers:    make(http.Header),
				Body:       s.getInstanceInfo(),
			}
		} else if handler, ok := s.routes[service]; ok {
			// 路由转发
			response, err = handler(request, w, s.options)
		} else {
			err = createHttpError(http.StatusNotFound, "Not Found")
		}
	}
}

func (s *BareServer) Handle(pattern string, handler RouteCallback) {
	s.routes[pattern] = handler
}

func (s *BareServer) HandleSocket(pattern string, handler SocketRouteCallback) {
	s.socketRoutes[pattern] = handler
}

func (s *BareServer) Start() error {
	mux := http.NewServeMux()

	// Serve static files from the specified directory
	staticFileServer := http.FileServer(http.Dir(s.options.StaticDir))
	mux.Handle("/", http.StripPrefix("/", staticFileServer))

	mux.HandleFunc(s.options.APIPath, func(w http.ResponseWriter, r *http.Request) {
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

	// Define HTTP and HTTPS servers
	var httpServer *http.Server
	if len(s.options.AddrHttp) >= 3 {
		httpServer = &http.Server{
			Addr:         s.options.AddrHttp,
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}
		// Start HTTP server in a separate goroutine
		go func() {
			log.Println("Starting HTTP server on port ", s.options.AddrHttp)
			if err := httpServer.ListenAndServe(); err != nil {
				log.Fatalf("HTTP server failed: %v", err)
			}
		}()

	}

	var httpsServer *http.Server
	if len(s.options.AddrHttps) >= 3 {
		httpsServer = &http.Server{
			Addr:         s.options.AddrHttps,
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			// Configure TLS settings
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS13, // Ensure TLS 1.3 is used (or adjust as needed)
			},
		}
		// Start HTTPS server
		go func() {
			log.Println("Starting HTTPS server on port ", s.options.AddrHttps)
			err := httpsServer.ListenAndServeTLS(s.options.CertFile, s.options.KeyFile)
			if err != nil {
				log.Fatalf("HTTPS server failed: %v", err)
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop

	fmt.Println("Shutting down server...")

	if httpServer != nil {
		if err := httpServer.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error shutting down server: %s\n", err)
		}
	}

	if httpsServer != nil {
		if err := httpsServer.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error shutting down server: %s\n", err)
		}
	}

	return nil
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

func JSON(w http.ResponseWriter, statusCode int, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	return json.NewEncoder(w).Encode(data)
}
