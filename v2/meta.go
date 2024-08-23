package v2

import "net/http"

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
