package v1

import "net/http"

type MetaV1 struct {
	V        int             `json:"v"`
	Response *MetaV1Response `json:"response,omitempty"`
}

type MetaV1Response struct {
	Headers http.Header `json:"headers"`
}
