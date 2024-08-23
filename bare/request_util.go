package bare

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

func RandomHex(byteLength int) string {
	bytes := make([]byte, byteLength)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes)
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
