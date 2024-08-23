package v3

import "net/http"

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
