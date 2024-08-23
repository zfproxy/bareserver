package bare

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const (
	maxHeaderValue = 3072
)

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
