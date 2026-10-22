package inbound

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type endpoint struct {
	host string
	port uint16
}

func (e endpoint) authority() string { return net.JoinHostPort(e.host, strconv.Itoa(int(e.port))) }

func parseEndpoint(authority string, defaultPort uint16) (endpoint, error) {
	if authority == "" || strings.ContainsAny(authority, "/?#@\\%") {
		return endpoint{}, errors.New("invalid target authority")
	}
	for _, c := range authority {
		if c <= 0x20 || c >= 0x7f {
			return endpoint{}, errors.New("invalid target authority")
		}
	}
	u, err := url.Parse("http://" + authority)
	if err != nil || u.Host != authority || u.User != nil || u.Path != "" {
		return endpoint{}, errors.New("invalid target authority")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if !validHost(host) {
		return endpoint{}, errors.New("invalid target host")
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	port := defaultPort
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil || n == 0 {
			return endpoint{}, errors.New("invalid target port")
		}
		port = uint16(n)
	} else if strings.HasSuffix(authority, ":") {
		return endpoint{}, errors.New("missing target port")
	}
	if port == 0 {
		return endpoint{}, errors.New("missing target port")
	}
	return endpoint{host: host, port: port}, nil
}

func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
