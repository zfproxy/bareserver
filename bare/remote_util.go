package bare

import (
	"fmt"
	"net/url"
)

func RemoteToURL(remote map[string]string) (*url.URL, error) {
	port := remote["port"]
	if port == "" {
		if remote["protocol"] == "http:" {
			port = "80"
		} else if remote["protocol"] == "https:" {
			port = "443"
		}
	}

	urlStr := fmt.Sprintf("%s//%s:%s%s", remote["protocol"], remote["host"], port, remote["path"])
	return url.Parse(urlStr)
}
