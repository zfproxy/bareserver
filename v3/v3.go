package v3

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/zfproxy/bareserver/bare"
)

var nullBodyStatus = []int{101, 204, 205, 304}
var forbiddenSendHeaders = []string{"connection", "content-length", "transfer-encoding"}
var forbiddenForwardHeaders = []string{"connection", "transfer-encoding", "host", "origin", "referer"}
var forbiddenPassHeaders = []string{"vary", "connection", "transfer-encoding", "access-control-allow-headers", "access-control-allow-methods", "access-control-expose-headers", "access-control-max-age", "access-control-request-headers", "access-control-request-method"}
var defaultForwardHeaders = []string{"accept-encoding", "accept-language"}
var defaultPassHeaders = []string{"content-encoding", "content-length", "last-modified"}
var defaultCacheForwardHeaders = []string{"if-modified-since", "if-none-match", "cache-control"}
var defaultCachePassHeaders = []string{"cache-control", "etag"}

var splitHeaderValue = regexp.MustCompile(`,\s*`)

const cacheNotModified = 304

func Register(server *bare.BareServer) {
	server.Handle("/v3/", v3Handler)
	server.HandleSocket("/v3/", v3WSHandler)
	server.Register("v3")
}

func loadForwardedHeaders(forward []string, target http.Header, request *bare.BareRequest) {
	for _, header := range forward {
		if value := request.Header.Get(header); value != "" {
			target.Set(header, value)
		}
	}
}

func readHeaders(request *bare.BareRequest) (map[string]interface{}, error) {
	sendHeaders := make(http.Header)
	passHeaders := append([]string{}, defaultPassHeaders...)
	var passStatus []int
	forwardHeaders := append([]string{}, defaultForwardHeaders...)

	cache, _ := strconv.ParseBool(request.URL.Query().Get("cache"))

	if cache {
		passHeaders = append(passHeaders, defaultCachePassHeaders...)
		passStatus = append(passStatus, cacheNotModified)
		forwardHeaders = append(forwardHeaders, defaultCacheForwardHeaders...)
	}

	headers := bare.JoinHeaders(request.Header)

	xBareURL := headers.Get("x-bare-url")
	if xBareURL == "" {
		return nil, &bare.BareError{Status: 400, Code: "MISSING_BARE_HEADER", ID: "request.headers.x-bare-url", Message: "Header was not specified.", Stack: ""}
	}

	remote, err := url.Parse(xBareURL)
	if err != nil {
		return nil, &bare.BareError{Status: 400, Code: "INVALID_BARE_HEADER", ID: "request.headers.x-bare-url", Message: "Invalid URL.", Stack: ""}
	}

	xBareHeaders := headers.Get("x-bare-headers")
	if xBareHeaders == "" {
		return nil, &bare.BareError{Status: 400, Code: "MISSING_BARE_HEADER", ID: "request.headers.x-bare-headers", Message: "Header was not specified.", Stack: ""}
	}

	var jsonHeaders map[string]interface{}
	if err := json.Unmarshal([]byte(xBareHeaders), &jsonHeaders); err != nil {
		return nil, &bare.BareError{Status: 400, Code: "INVALID_BARE_HEADER", ID: "request.headers.x-bare-headers", Message: "Header contained invalid JSON.", Stack: ""}
	}

	for header, value := range jsonHeaders {
		if bare.Contains(forbiddenSendHeaders, strings.ToLower(header)) {
			continue
		}
		switch v := value.(type) {
		case string:
			sendHeaders.Set(header, v)
		case []interface{}:
			for _, v := range v {
				if strVal, ok := v.(string); ok {
					sendHeaders.Add(header, strVal)
				} else {
					return nil, &bare.BareError{Status: 400, Code: "INVALID_BARE_HEADER", ID: fmt.Sprintf("bare.headers.%s", header), Message: "Header value must be a string or an array of strings.", Stack: ""}
				}
			}
		default:
			return nil, &bare.BareError{Status: 400, Code: "INVALID_BARE_HEADER", ID: fmt.Sprintf("bare.headers.%s", header), Message: "Header value must be a string or an array of strings.", Stack: ""}
		}
	}

	if xBarePassStatus := headers.Get("x-bare-pass-status"); xBarePassStatus != "" {
		for _, value := range splitHeaderValue.Split(xBarePassStatus, -1) {
			number, err := strconv.Atoi(value)
			if err != nil {
				return nil, &bare.BareError{Status: 400, Code: "INVALID_BARE_HEADER", ID: "request.headers.x-bare-pass-status", Message: "Array contained non-number value.", Stack: ""}
			}
			passStatus = append(passStatus, number)
		}
	}

	if xBarePassHeaders := headers.Get("x-bare-pass-headers"); xBarePassHeaders != "" {
		for _, header := range splitHeaderValue.Split(xBarePassHeaders, -1) {
			header = strings.ToLower(header)
			if bare.Contains(forbiddenPassHeaders, header) {
				return nil, &bare.BareError{Status: 400, Code: "FORBIDDEN_BARE_HEADER", ID: "request.headers.x-bare-forward-headers", Message: "A forbidden header was passed.", Stack: ""}
			}
			passHeaders = append(passHeaders, header)
		}
	}

	if xBareForwardHeaders := headers.Get("x-bare-forward-headers"); xBareForwardHeaders != "" {
		for _, header := range splitHeaderValue.Split(xBareForwardHeaders, -1) {
			header = strings.ToLower(header)
			if bare.Contains(forbiddenForwardHeaders, header) {
				return nil, &bare.BareError{Status: 400, Code: "FORBIDDEN_BARE_HEADER", ID: "request.headers.x-bare-forward-headers", Message: "A forbidden header was forwarded.", Stack: ""}
			}
			forwardHeaders = append(forwardHeaders, header)
		}
	}

	result := map[string]interface{}{
		"remote":         remote,
		"sendHeaders":    sendHeaders,
		"passHeaders":    passHeaders,
		"passStatus":     passStatus,
		"forwardHeaders": forwardHeaders,
	}

	return result, nil
}

func v3WSHandler(request *bare.BareRequest, clientConn *websocket.Conn, options *bare.Options) error {
	defer clientConn.Close()

	messageType, message, err := clientConn.ReadMessage()
	if err != nil {
		return fmt.Errorf("error reading initial message from client: %w", err)
	}

	if messageType != websocket.TextMessage {
		return errors.New("the first WebSocket message was not a text frame")
	}

	var connectPacket bare.SocketClientToServer
	if err := json.Unmarshal(message, &connectPacket); err != nil {
		return fmt.Errorf("error unmarshalling client connection packet: %w", err)
	}

	if connectPacket.Type != "connect" {
		return errors.New("client did not send open packet")
	}

	loadForwardedHeaders(connectPacket.ForwardHeaders, connectPacket.Headers, request)

	_, remoteSocket, httpReq, err := bare.WebSocketFetch(request, connectPacket.Headers, &url.URL{Scheme: "wss", Host: connectPacket.Remote}, connectPacket.Protocols, options)
	if err != nil {
		return fmt.Errorf("error establishing remote WebSocket connection: %w", err)
	}
	defer remoteSocket.Close()

	openPacket := bare.SocketServerToClient{
		Type:       "open",
		Protocol:   remoteSocket.Subprotocol(),
		SetCookies: httpReq.Header["Set-Cookie"],
	}
	openPacketJSON, _ := json.Marshal(openPacket)

	if err := clientConn.WriteMessage(websocket.TextMessage, openPacketJSON); err != nil {
		return fmt.Errorf("error sending open packet to client: %w", err)
	}

	go func() {
		defer func() {
			clientConn.Close()
			remoteSocket.Close()
		}()

		for {
			messageType, message, err := remoteSocket.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					if options.LogErrors {
						fmt.Fprintf(os.Stderr, "Error reading message from remote WebSocket: %v\n", err)
					}
				}
				return
			}
			if err := clientConn.WriteMessage(messageType, message); err != nil {
				if options.LogErrors {
					fmt.Fprintf(os.Stderr, "Error writing message to client WebSocket: %v\n", err)
				}
				return
			}
		}
	}()

	defer func() {
		clientConn.Close()
		remoteSocket.Close()
	}()

	for {
		messageType, message, err := clientConn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				if options.LogErrors {
					fmt.Fprintf(os.Stderr, "Error reading message from client WebSocket: %v\n", err)
				}
			}
			return nil
		}

		if err := remoteSocket.WriteMessage(messageType, message); err != nil {
			if options.LogErrors {
				fmt.Fprintf(os.Stderr, "Error writing message to remote WebSocket: %v\n", err)
			}
			return nil
		}
	}
}

func v3Handler(request *bare.BareRequest, w http.ResponseWriter, options *bare.Options) (*bare.Response, error) {
	headersData, err := readHeaders(request)
	if err != nil {
		return nil, err
	}

	remote := headersData["remote"].(*url.URL)
	sendHeaders := headersData["sendHeaders"].(http.Header)
	passHeaders := headersData["passHeaders"].([]string)
	passStatus := headersData["passStatus"].([]int)
	forwardHeaders := headersData["forwardHeaders"].([]string)

	loadForwardedHeaders(forwardHeaders, sendHeaders, request)

	response, err := bare.BareFetch(request, sendHeaders, remote, options)
	if err != nil {
		return nil, err
	}
	// defer response.Body.Close()

	responseHeaders := make(http.Header)

	for _, header := range passHeaders {
		if values := response.Header[header]; len(values) > 0 {
			responseHeaders.Set(header, bare.FlattenHeader(values))
		}
	}

	status := http.StatusOK
	if bare.ContainsInt(passStatus, response.StatusCode) {
		status = response.StatusCode
	}

	if status != cacheNotModified {
		responseHeaders.Set("x-bare-status", strconv.Itoa(response.StatusCode))
		responseHeaders.Set("x-bare-status-text", response.Status)
		headersToPass := bare.MapHeadersFromArray(bare.RawHeaderNames(response.Header), response.Header)
		headersJSON, err := json.Marshal(headersToPass)
		if err != nil {
			return nil, err
		}
		responseHeaders.Set("x-bare-headers", string(headersJSON))
	}

	responseBody := io.ReadCloser(response.Body)
	if !bare.ContainsInt(nullBodyStatus, status) {
		responseBody = response.Body
	}

	return &bare.Response{
		StatusCode: status,
		Headers:    bare.SplitHeaders(responseHeaders),
		Body:       responseBody,
	}, nil
}
