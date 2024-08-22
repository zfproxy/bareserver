package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/zfproxy/bareserver/bare"
)

type MetaV1 struct {
	V        int             `json:"v"`
	Response *MetaV1Response `json:"response,omitempty"`
}

type MetaV1Response struct {
	Headers http.Header `json:"headers"`
}

var forbiddenSendHeaders = []string{"connection", "content-length", "transfer-encoding"}
var forbiddenForwardHeaders = []string{"connection", "transfer-encoding", "origin", "referer"}

const metaExpiration = 30 * time.Second

var bareserver *bare.BareServer

func Register(server *bare.BareServer) {
	bareserver = server

	server.Handle("/v1/", v1Handler)
	server.Handle("/v1/ws-meta", v1WSMetaHandler)
	server.Handle("/v1/ws-new-meta", v1WSNewMetaHandler)
	server.HandleSocket("/v1/", v1SocketHandler)
	server.Register("v1")
}

func readHeaders(request *bare.BareRequest) (map[string]interface{}, error) {

	remote := make(map[string]string)
	headers := make(http.Header)

	for _, remoteProp := range []string{"host", "port", "protocol", "path"} {
		header := fmt.Sprintf("x-bare-%s", remoteProp)
		value := request.Header.Get(header)
		if value == "" {
			return nil, &bare.BareError{Status: 400, Code: "MISSING_BARE_HEADER", ID: fmt.Sprintf("request.headers.%s", header), Message: "Header was not specified.", Stack: ""}
		}

		switch remoteProp {
		case "port":
			if _, err := strconv.Atoi(value); err != nil {
				return nil, &bare.BareError{Status: 400, Code: "INVALID_BARE_HEADER", ID: fmt.Sprintf("request.headers.%s", header), Message: "Header was not a valid integer.", Stack: ""}
			}
		case "protocol":
			if !bare.Contains([]string{"http:", "https:", "ws:", "wss:"}, value) {
				return nil, &bare.BareError{Status: 400, Code: "INVALID_BARE_HEADER", ID: fmt.Sprintf("request.headers.%s", header), Message: "Header was invalid.", Stack: ""}
			}
		}

		remote[remoteProp] = value
	}

	xBareHeaders := request.Header.Get("x-bare-headers")
	if xBareHeaders == "" {
		return nil, &bare.BareError{Status: 400, Code: "MISSING_BARE_HEADER", ID: "request.headers.x-bare-headers", Message: "Header was not specified.", Stack: ""}
	}

	var jsonHeaders map[string]interface{}
	if err := json.Unmarshal([]byte(xBareHeaders), &jsonHeaders); err != nil {
		return nil, &bare.BareError{Status: 400, Code: "INVALID_BARE_HEADER", ID: "request.headers.x-bare-headers", Message: fmt.Sprintf("Header contained invalid JSON. (%s)", err.Error()), Stack: ""}
	}

	for header, value := range jsonHeaders {
		if bare.Contains(forbiddenSendHeaders, strings.ToLower(header)) {
			continue
		}

		switch v := value.(type) {
		case string:
			headers.Set(header, v)
		case []interface{}:
			for _, v := range v {
				if strVal, ok := v.(string); ok {
					headers.Add(header, strVal)
				} else {
					return nil, &bare.BareError{Status: 400, Code: "INVALID_BARE_HEADER", ID: fmt.Sprintf("bare.headers.%s", header), Message: "Header value must be a string or an array of strings.", Stack: ""}
				}
			}
		default:
			return nil, &bare.BareError{Status: 400, Code: "INVALID_BARE_HEADER", ID: fmt.Sprintf("bare.headers.%s", header), Message: "Header value must be a string or an array of strings.", Stack: ""}
		}
	}

	xBareForwardHeaders := request.Header.Get("x-bare-forward-headers")
	if xBareForwardHeaders == "" {
		return nil, &bare.BareError{Status: 400, Code: "MISSING_BARE_HEADER", ID: "request.headers.x-bare-forward-headers", Message: "Header was not specified.", Stack: ""}
	}

	var forwardHeaders []string
	if err := json.Unmarshal([]byte(xBareForwardHeaders), &forwardHeaders); err != nil {
		return nil, &bare.BareError{Status: 400, Code: "INVALID_BARE_HEADER", ID: "request.headers.x-bare-forward-headers", Message: fmt.Sprintf("Header contained invalid JSON. (%s)", err.Error()), Stack: ""}
	}

	for i, header := range forwardHeaders {
		forwardHeaders[i] = strings.ToLower(header)
	}

	for _, header := range forbiddenForwardHeaders {
		if bare.Contains(forwardHeaders, header) {
			return nil, &bare.BareError{Status: 400, Code: "FORBIDDEN_BARE_HEADER", ID: "request.headers.x-bare-forward-headers", Message: "A forbidden header was passed.", Stack: ""}
		}
	}

	loadForwardedHeaders(forwardHeaders, headers, request)

	remoteURL, err := bare.RemoteToURL(remote)
	if err != nil {
		return nil, &bare.BareError{Status: 400, Code: "INVALID_BARE_HEADER", ID: "request.headers.x-bare-(host|port|protocol|path)", Message: "Invalid remote.", Stack: ""}
	}

	return map[string]interface{}{
		"remote":         remoteURL,
		"headers":        headers,
		"forwardHeaders": forwardHeaders,
	}, nil
}

func loadForwardedHeaders(forward []string, target http.Header, request *bare.BareRequest) {
	for _, header := range forward {
		if value := request.Header.Get(header); value != "" {
			target.Set(header, value)
		}
	}
}

func v1Handler(request *bare.BareRequest, w http.ResponseWriter, options *bare.Options) (*bare.Response, error) {
	headersData, err := readHeaders(request)
	if err != nil {
		return nil, err
	}

	remote := headersData["remote"].(*url.URL)
	headers := headersData["headers"].(http.Header)

	response, err := bare.BareFetch(request, headers, remote, options)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	responseHeaders := make(http.Header)

	for header, values := range response.Header {
		if header == "Content-Encoding" || header == "X-Content-Encoding" {
			responseHeaders.Set("Content-Encoding", bare.FlattenHeader(values))
		} else if header == "Content-Length" {
			responseHeaders.Set("Content-Length", bare.FlattenHeader(values))
		}
	}

	responseHeaders.Set("x-bare-headers", response.Header.Get("x-bare-headers"))
	responseHeaders.Set("x-bare-status", strconv.Itoa(response.StatusCode))
	responseHeaders.Set("x-bare-status-text", response.Status)

	return &bare.Response{
		StatusCode: http.StatusOK,
		Headers:    responseHeaders,
		Body:       response.Body,
	}, nil
}

func v1WSMetaHandler(request *bare.BareRequest, w http.ResponseWriter, options *bare.Options) (*bare.Response, error) {
	if request.Method == http.MethodOptions {
		return &bare.Response{
			StatusCode: http.StatusOK,
			Headers:    make(http.Header),
		}, nil
	}

	id := request.Header.Get("x-bare-id")
	if id == "" {
		return nil, &bare.BareError{Status: 400, Code: "MISSING_BARE_HEADER", ID: "request.headers.x-bare-id", Message: "Header was not specified.", Stack: ""}
	}

	meta, err := bareserver.DB().Get(id)
	if err != nil {
		return nil, &bare.BareError{Status: 500, Code: "DATABASE_ERROR", ID: "database", Message: "Failed to retrieve metadata.", Stack: ""}
	}
	if meta == "" {
		return nil, &bare.BareError{Status: 400, Code: "INVALID_BARE_HEADER", ID: "request.headers.x-bare-id", Message: "Unregistered ID.", Stack: ""}
	}

	var metaV1 *MetaV1
	if err := json.Unmarshal([]byte(meta), &metaV1); err != nil {
		return nil, &bare.BareError{Status: 500, Code: "DATABASE_ERROR", ID: "database", Message: "Failed to parse metadata.", Stack: ""}
	}

	if metaV1.V != 1 {
		return nil, &bare.BareError{Status: 400, Code: "INVALID_BARE_HEADER", ID: "request.headers.x-bare-id", Message: "Unregistered ID.", Stack: ""}
	}

	if err := bareserver.DB().Delete(id); err != nil {
		return nil, &bare.BareError{Status: 500, Code: "DATABASE_ERROR", ID: "database", Message: "Failed to delete metadata.", Stack: ""}
	}

	return &bare.Response{
		StatusCode: http.StatusOK,
		Headers:    make(http.Header),
		Body:       bytes.NewReader([]byte(`{"headers":` + meta + `}`)),
	}, nil
}

func v1WSNewMetaHandler(request *bare.BareRequest, w http.ResponseWriter, options *bare.Options) (*bare.Response, error) {
	id := bare.RandomHex(16)
	meta := &MetaV1{
		V: 1,
	}
	metaJSON, _ := json.Marshal(meta)
	if err := bareserver.DB().Set(id, string(metaJSON), metaExpiration); err != nil {
		return nil, &bare.BareError{Status: 500, Code: "DATABASE_ERROR", ID: "database", Message: "Failed to store metadata.", Stack: ""}
	}

	return &bare.Response{
		StatusCode: http.StatusOK,
		Body:       bytes.NewReader([]byte(id)),
	}, nil
}

func v1SocketHandler(request *bare.BareRequest, socket *websocket.Conn, options *bare.Options) error {
	defer socket.Close()

	if request.Header.Get("Sec-Websocket-Protocol") == "" {
		return nil
	}

	parts := strings.SplitN(request.Header.Get("Sec-Websocket-Protocol"), ",", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) != "bare" {
		return nil
	}

	var metaData struct {
		Remote         map[string]string `json:"remote"`
		Headers        http.Header       `json:"headers"`
		ForwardHeaders []string          `json:"forward_headers"`
		ID             string            `json:"id"`
	}

	data, err := bare.DecodeProtocol(strings.TrimSpace(parts[1]))
	if err != nil {
		return fmt.Errorf("error decoding protocol data: %w", err)
	}

	if err := json.Unmarshal([]byte(data), &metaData); err != nil {
		return fmt.Errorf("error unmarshalling metadata: %w", err)
	}

	loadForwardedHeaders(metaData.ForwardHeaders, metaData.Headers, request)

	remoteURL, err := bare.RemoteToURL(metaData.Remote)
	if err != nil {
		return fmt.Errorf("error parsing remote URL: %w", err)
	}

	remoteResponse, remoteConn, err := bare.BareUpgradeFetch(request, metaData.Headers, remoteURL, options)
	if err != nil {
		return fmt.Errorf("error upgrading to websocket: %w", err)
	}
	defer remoteConn.Close()

	wsConn, _, err := websocket.NewClient(remoteConn, remoteURL, request.Header, 1024, 1024)
	if err != nil {
		return fmt.Errorf("error upgrading to WebSocket: %w", err)
	}
	defer wsConn.Close()

	if metaData.ID != "" {
		meta, err := bareserver.DB().Get(metaData.ID)
		if err != nil {
			return &bare.BareError{Status: 500, Code: "DATABASE_ERROR", ID: "database", Message: "Failed to retrieve metadata.", Stack: ""}
		}
		if meta != "" {
			var metaV1 *MetaV1
			if err := json.Unmarshal([]byte(meta), &metaV1); err != nil {
				return &bare.BareError{Status: 500, Code: "DATABASE_ERROR", ID: "database", Message: "Failed to parse metadata.", Stack: ""}
			}
			if metaV1.V == 1 {
				metaV1.Response = &MetaV1Response{
					Headers: remoteResponse.Header,
				}
				updatedMetaJSON, err := json.Marshal(metaV1)
				if err != nil {
					return err
				}
				if err := bareserver.DB().Set(metaData.ID, string(updatedMetaJSON), metaExpiration); err != nil {
					return &bare.BareError{Status: 500, Code: "DATABASE_ERROR", ID: "database", Message: "Failed to store metadata.", Stack: ""}
				}
			}
		}
	}

	responseHeaders := fmt.Sprintf(
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: bare\r\nSec-WebSocket-Accept: %s\r\n",
		remoteResponse.Header.Get("Sec-WebSocket-Accept"),
	)
	if extensions := remoteResponse.Header.Get("Sec-Websocket-Extensions"); extensions != "" {
		responseHeaders += fmt.Sprintf("Sec-WebSocket-Extensions: %s\r\n", extensions)
	}
	responseHeaders += "\r\n"

	if err := socket.WriteMessage(websocket.TextMessage, []byte(responseHeaders)); err != nil {
		return fmt.Errorf("error writing response headers: %w", err)
	}

	go func() {
		defer func() {
			socket.Close()
			remoteConn.Close()
			wsConn.Close()
		}()

		for {
			messageType, message, err := wsConn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					if options.LogErrors {
						fmt.Fprintf(os.Stderr, "Error reading message from remote WebSocket: %v\n", err)
					}
				}
				return
			}

			if err := socket.WriteMessage(messageType, message); err != nil {
				if options.LogErrors {
					fmt.Fprintf(os.Stderr, "Error writing message to client WebSocket: %v\n", err)
				}
				return
			}
		}
	}()

	defer func() {
		socket.Close()
		remoteConn.Close()
		wsConn.Close()
	}()

	for {
		messageType, message, err := socket.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				if options.LogErrors {
					fmt.Fprintf(os.Stderr, "Error reading message from client WebSocket: %v\n", err)
				}
			}
			return nil
		}

		if err := wsConn.WriteMessage(messageType, message); err != nil {
			if options.LogErrors {
				fmt.Fprintf(os.Stderr, "Error writing message to remote WebSocket: %v\n", err)
			}
			return nil
		}
	}
}
