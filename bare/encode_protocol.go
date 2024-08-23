package bare

import "net/url"

func DecodeProtocol(protocol string) (string, error) {
	return url.PathUnescape(protocol)
}
