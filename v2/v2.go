package v2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/zfproxy/bareserver/bare"
)

type MetaV2 struct {
	V              int             `json:"v"`
	Response       *MetaV2Response `json:"response,omitempty"`
	SendHeaders    http.Header     `json:"sendHeaders"`
	Remote         string          `json:"remote"`
	ForwardHeaders []string        `json:"forwardHeaders"`
}

type MetaV2Response struct {
	Status     int         `json:"status"`
	StatusText string      `json:"statusText"`
	Headers    http.Header `json:"headers"`
}

func Register(server *bare.BareServer) {
	nullBodyStatus := []int{101, 204, 205, 304}
	forbiddenSendHeaders := []string{"connection", "content-length", "transfer-encoding"}
	forbiddenForwardHeaders := []string{"connection", "transfer-encoding", "host", "origin", "referer"}
	forbiddenPassHeaders := []string{"vary", "connection", "transfer-encoding", "access-control-allow-headers", "access-control-allow-methods", "access-control-expose-headers", "access-control-max-age", "access-control-request-headers", "access-control-request-method"}
	defaultForwardHeaders := []string{"accept-encoding", "accept-language", "sec-websocket-extensions", "sec-websocket-key", "sec-websocket-version"}
	defaultPassHeaders := []string{"content-encoding", "content-length", "last-modified"}
	defaultCacheForwardHeaders := []string{"if-modified-since", "if-none-match", "cache-control"}
	defaultCachePassHeaders := []string{"cache-control", "etag"}
	cacheNotModified := 304

	loadForwardedHeaders := func(forward []string, target http.Header, request *bare.BareRequest) {
		for _, header := range forward {
			if value := request.Header.Get(header); value != "" {
				target.Set(header, value)
			}
		}
	}

	splitHeaderValue := regexp.MustCompile(`,\s*`)

	readHeaders := func(request *bare.BareRequest) (map[string]interface{}, error) {
		remote := make(map[string]string)
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

		for _, remoteProp := range []string{"host", "port", "protocol", "path"} {
			header := fmt.Sprintf("x-bare-%s", remoteProp)
			value := headers.Get(header)
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

		xBareHeaders := headers.Get("x-bare-headers")
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

		remoteURL, err := bare.RemoteToURL(remote)
		if err != nil {
			return nil, &bare.BareError{Status: 400, Code: "INVALID_BARE_HEADER", ID: "request.headers.x-bare-(host|port|protocol|path)", Message: "Invalid remote.", Stack: ""}
		}
		result := map[string]interface{}{
			"remote":         remoteURL,
			"sendHeaders":    sendHeaders,
			"passHeaders":    passHeaders,
			"passStatus":     passStatus,
			"forwardHeaders": forwardHeaders,
		}

		return result, nil
	}

	server.Handle("/v2/", func(request *bare.BareRequest, w http.ResponseWriter, options *bare.Options) (*bare.Response, error) {
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
		defer response.Body.Close()

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

		responseBody := io.Reader(nil)
		if !bare.ContainsInt(nullBodyStatus, status) {
			responseBody = response.Body
		}

		return &bare.Response{
			StatusCode: status,
			Headers:    bare.SplitHeaders(responseHeaders),
			Body:       responseBody,
		}, nil
	})

	metaExpiration := 30 * time.Second

	server.Handle("/v2/ws-meta", func(request *bare.BareRequest, w http.ResponseWriter, options *bare.Options) (*bare.Response, error) {
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

		meta, err := server.DB().Get(id)
		if err != nil {
			return nil, &bare.BareError{Status: 500, Code: "DATABASE_ERROR", ID: "database", Message: "Failed to retrieve metadata.", Stack: ""}
		}

		if meta == "" {
			return nil, &bare.BareError{Status: 400, Code: "INVALID_BARE_HEADER", ID: "request.headers.x-bare-id", Message: "Unregistered ID.", Stack: ""}
		}

		var metaV2 *MetaV2
		if err := json.Unmarshal([]byte(meta), &metaV2); err != nil {
			return nil, &bare.BareError{Status: 500, Code: "DATABASE_ERROR", ID: "database", Message: "Failed to parse metadata.", Stack: ""}
		}

		if metaV2.V != 2 {
			return nil, &bare.BareError{Status: 400, Code: "INVALID_BARE_HEADER", ID: "request.headers.x-bare-id", Message: "Unregistered ID.", Stack: ""}
		}

		if metaV2.Response == nil {
			return nil, &bare.BareError{Status: 400, Code: "INVALID_BARE_HEADER", ID: "request.headers.x-bare-id", Message: "Metadata not ready.", Stack: ""}
		}

		if err := server.DB().Delete(id); err != nil {
			return nil, &bare.BareError{Status: 500, Code: "DATABASE_ERROR", ID: "database", Message: "Failed to delete metadata.", Stack: ""}
		}

		responseHeaders := make(http.Header)
		responseHeaders.Set("x-bare-status", strconv.Itoa(metaV2.Response.Status))
		responseHeaders.Set("x-bare-status-text", metaV2.Response.StatusText)
		headersJSON, err := json.Marshal(metaV2.Response.Headers)
		if err != nil {
			return nil, err
		}
		responseHeaders.Set("x-bare-headers", string(headersJSON))

		return &bare.Response{
			StatusCode: http.StatusOK,
			Headers:    bare.SplitHeaders(responseHeaders),
		}, nil
	})

	server.Handle("/v2/ws-new-meta", func(request *bare.BareRequest, w http.ResponseWriter, options *bare.Options) (*bare.Response, error) {
		headersData, err := readHeaders(request)
		if err != nil {
			return nil, err
		}

		remote := headersData["remote"].(*url.URL)
		sendHeaders := headersData["sendHeaders"].(http.Header)
		forwardHeaders := headersData["forwardHeaders"].([]string)

		id := bare.RandomHex(16)
		meta := &MetaV2{
			V:              2,
			Remote:         remote.String(),
			SendHeaders:    sendHeaders,
			ForwardHeaders: forwardHeaders,
		}

		metaJSON, err := json.Marshal(meta)
		if err != nil {
			return nil, err
		}

		if err := server.DB().Set(id, string(metaJSON), metaExpiration); err != nil {
			return nil, &bare.BareError{Status: 500, Code: "DATABASE_ERROR", ID: "database", Message: "Failed to store metadata.", Stack: ""}
		}

		return &bare.Response{
			StatusCode: http.StatusOK,
			Body:       bytes.NewReader([]byte(id)),
		}, nil
	})

	server.HandleSocket("/v2/", func(request *bare.BareRequest, socket *websocket.Conn, options *bare.Options) error {
		defer socket.Close()

		if request.Header.Get("Sec-Websocket-Protocol") == "" {
			return nil
		}

		id := request.Header.Get("Sec-Websocket-Protocol")
		meta, err := server.DB().Get(id)
		if err != nil {
			return &bare.BareError{Status: 500, Code: "DATABASE_ERROR", ID: "database", Message: "Failed to retrieve metadata.", Stack: ""}
		}

		if meta == "" {
			return nil
		}

		var metaV2 *MetaV2
		if err := json.Unmarshal([]byte(meta), &metaV2); err != nil {
			return &bare.BareError{Status: 500, Code: "DATABASE_ERROR", ID: "database", Message: "Failed to parse metadata.", Stack: ""}
		}

		if metaV2.V != 2 {
			return nil
		}

		loadForwardedHeaders(metaV2.ForwardHeaders, metaV2.SendHeaders, request)

		remoteURL, err := url.Parse(metaV2.Remote)
		if err != nil {
			return &bare.BareError{Status: 400, Code: "INVALID_BARE_HEADER", ID: "request.headers.x-bare-(host|port|protocol|path)", Message: "Invalid remote.", Stack: ""}
		}

		remoteResponse, remoteConn, err := bare.BareUpgradeFetch(request, metaV2.SendHeaders, remoteURL, options)
		if err != nil {
			return err
		}
		defer remoteConn.Close()

		wsConn, _, err := websocket.NewClient(remoteConn, remoteURL, request.Header, 1024, 1024)
		if err != nil {
			return fmt.Errorf("error upgrading to WebSocket: %w", err)
		}
		defer wsConn.Close()

		metaV2.Response = &MetaV2Response{
			Status:     remoteResponse.StatusCode,
			StatusText: remoteResponse.Status,
			Headers:    remoteResponse.Header,
		}
		updatedMetaJSON, err := json.Marshal(metaV2)
		if err != nil {
			return err
		}
		if err := server.DB().Set(id, string(updatedMetaJSON), metaExpiration); err != nil {
			return &bare.BareError{Status: 500, Code: "DATABASE_ERROR", ID: "database", Message: "Failed to store metadata.", Stack: ""}
		}

		responseHeaders := fmt.Sprintf(
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: %s\r\n",
			id,
		)
		if extensions := remoteResponse.Header.Get("Sec-Websocket-Extensions"); extensions != "" {
			responseHeaders += fmt.Sprintf("Sec-WebSocket-Extensions: %s\r\n", extensions)
		}
		if accept := remoteResponse.Header.Get("Sec-WebSocket-Accept"); accept != "" {
			responseHeaders += fmt.Sprintf("Sec-WebSocket-Accept: %s\r\n", accept)
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
	})

	server.Register("v2")
}
