package bare

import (
	"net/http"
	"strings"
)

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
