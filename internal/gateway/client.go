// Package auth implements the gateway controller login protocol.
package gateway

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrSessionInvalid requires an explicit authentication rejection. Network,
	// TLS and response decoding failures do not invalidate a cached session.
	ErrSessionInvalid  = errors.New("session is invalid or expired")
	ErrCaptchaRejected = errors.New("gateway rejected captcha")
	ErrLoginRejected   = errors.New("gateway rejected login")
)

const maxAPIResponse = 1 << 20

// Protocol holds the deployment-specific surface of the controller API. The
// request sequence and payload schema are fixed; names and paths are not.
type Protocol struct {
	APIBase       string // path prefix of the client API, without a trailing slash
	UserAgent     string
	SessionCookie string // name of the cookie that binds key, captcha and login
	RenewSalt     string // salt the gateway expects in the session-renewal digest
}

// Client owns one authentication flow. GenerateKey, GetCaptcha and Login must
// be called in sequence: the encryption key and captcha belong to its cookie.
// Session values returned by Login and ValidateSession are independent copies.
type Client struct {
	protocol   Protocol
	origin     *url.URL
	httpClient *http.Client
	cookie     string
	gatewayDNS netip.Addr
}

func NewClient(host string, port int, bindIP string, policy *tls.Config, protocol Protocol) (*Client, error) {
	host = strings.Trim(host, "[]")
	if host == "" || strings.ContainsAny(host, "/\\@?# \t\r\n") || port < 1 || port > 65535 {
		return nil, errors.New("invalid gateway host or port")
	}
	if !strings.HasPrefix(protocol.APIBase, "/") || protocol.UserAgent == "" || protocol.SessionCookie == "" {
		return nil, errors.New("incomplete gateway protocol profile")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if bindIP != "" {
		ip := net.ParseIP(bindIP)
		if ip == nil {
			return nil, errors.New("invalid gateway bind IP")
		}
		dialer.LocalAddr = &net.TCPAddr{IP: ip}
	}
	// The policy is built by the caller, so make the invariant explicit rather
	// than trusting that the two were derived from the same setting.
	if policy == nil {
		return nil, errors.New("gateway client needs a TLS policy")
	}
	if policy.ServerName != host {
		return nil, fmt.Errorf("TLS policy verifies %q but this client talks to %q", policy.ServerName, host)
	}
	c := &Client{
		protocol: protocol,
		origin:   &url.URL{Scheme: "https", Host: net.JoinHostPort(host, strconv.Itoa(port))},
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialContext: dialer.DialContext, TLSClientConfig: policy,
				ResponseHeaderTimeout:  15 * time.Second,
				IdleConnTimeout:        30 * time.Second,
				MaxResponseHeaderBytes: 64 << 10,
			},
			Timeout: 20 * time.Second,
		},
	}
	// The controller API has no redirect step. Refuse redirects before any cookie or
	// request body can leave the endpoint selected by the caller.
	c.httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return c, nil
}

func (c *Client) Close() {
	c.httpClient.CloseIdleConnections()
}

// GatewayDNS returns the DNS server advertised for this gateway by the last
// successful session validation. An absent or unmatched policy returns an
// invalid address; callers must not substitute a DNS server from another row.
func (c *Client) GatewayDNS() netip.Addr { return c.gatewayDNS }

type apiResponse struct {
	Code     string          `json:"code"`
	Messages string          `json:"messages"`
	Data     json.RawMessage `json:"data"`
}

// apiError deliberately omits the server's message: a gateway can echo login
// credentials into an error response. The message is only used for classifying
// captcha rejection inside Login.
type apiError struct{ message string }

func (*apiError) Error() string { return "gateway API rejected request" }

func readAPIResponse(resp *http.Response) (*apiResponse, error) {
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ErrSessionInvalid
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponse+1))
	if err != nil {
		return nil, fmt.Errorf("read gateway response: %w", err)
	}
	if len(body) > maxAPIResponse {
		return nil, errors.New("gateway API response is too large")
	}
	var res apiResponse
	if json.Unmarshal(body, &res) != nil {
		return nil, errors.New("invalid gateway API response")
	}
	// The controller uses 1001 when another login or an administrator revokes
	// this account session; it still responds with HTTP 200.
	if res.Code == "401" || res.Code == "403" || res.Code == "1001" {
		return nil, ErrSessionInvalid
	}
	if res.Code != "200" {
		return nil, &apiError{message: res.Messages}
	}
	return &res, nil
}

func (c *Client) request(ctx context.Context, method, path string, body io.Reader) (*apiResponse, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.origin.String()+c.protocol.APIBase+path, body)
	if err != nil {
		return nil, errors.New("cannot create gateway request")
	}
	req.Header.Set("User-Agent", c.protocol.UserAgent)
	req.Header.Set("Accept", "application/json")
	if c.cookie != "" {
		req.Header.Set("Cookie", c.cookie)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Strip net/http's URL wrapper; URLs and redirect errors may contain
		// server-controlled data. Retain the cause for timeout/cancel detection.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return nil, fmt.Errorf("execute gateway request: %w", err)
	}
	defer resp.Body.Close()
	res, err := readAPIResponse(resp)
	if err != nil {
		return nil, err
	}
	if err := c.updateCookie(resp); err != nil {
		return nil, err
	}
	return res, nil
}

func (c *Client) updateCookie(resp *http.Response) error {
	var found *http.Cookie
	for _, cookie := range resp.Cookies() {
		if cookie.Name == c.protocol.SessionCookie {
			if found != nil {
				return errors.New("gateway returned duplicate authentication cookies")
			}
			found = cookie
		}
	}
	if found != nil {
		c.cookie = ""
		if found.Value != "" && found.MaxAge >= 0 && (found.Expires.IsZero() || found.Expires.After(time.Now())) {
			c.cookie = (&http.Cookie{Name: found.Name, Value: found.Value, Quoted: found.Quoted}).String()
		}
	}
	return nil
}

func (c *Client) GenerateKey(ctx context.Context) (string, error) {
	res, err := c.request(ctx, http.MethodGet, "/auth/generateKey", nil)
	if err != nil {
		return "", fmt.Errorf("generate session key: %w", err)
	}
	var key string
	if json.Unmarshal(res.Data, &key) != nil || len(key) != aes.BlockSize {
		return "", errors.New("gateway returned an invalid session key")
	}
	if c.cookie == "" {
		return "", errors.New("gateway did not establish a session cookie")
	}
	return key, nil
}

func (c *Client) GetCaptcha(ctx context.Context) ([]byte, error) {
	res, err := c.request(ctx, http.MethodGet, "/auth/v2/getCaptcha", nil)
	if err != nil {
		return nil, fmt.Errorf("get captcha: %w", err)
	}
	var encoded string
	if json.Unmarshal(res.Data, &encoded) != nil || encoded == "" {
		return nil, errors.New("gateway returned an empty or invalid captcha")
	}
	image, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(image) == 0 {
		return nil, errors.New("gateway returned invalid captcha image data")
	}
	return image, nil
}

func (c *Client) Login(ctx context.Context, username, password, key, captcha string) (*Session, error) {
	if strings.TrimSpace(username) == "" || password == "" || strings.TrimSpace(captcha) == "" {
		return nil, errors.New("username, password and captcha are required")
	}
	if len(key) != aes.BlockSize {
		return nil, errors.New("invalid session encryption key")
	}
	encrypted, err := encryptPassword(password, key)
	if err != nil {
		return nil, errors.New("cannot encrypt login password")
	}
	payload, err := json.Marshal(struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		Code          string `json:"code"`
		IsFingerPrint bool   `json:"isFingerPrint"`
	}{Username: username, Password: encrypted, Code: captcha})
	if err != nil {
		return nil, errors.New("cannot encode login request")
	}
	res, err := c.request(ctx, http.MethodPost, "/auth/login", bytes.NewReader(payload))
	if err != nil {
		var rejected *apiError
		if errors.As(err, &rejected) && (strings.Contains(rejected.message, "验证码") || strings.Contains(strings.ToLower(rejected.message), "captcha")) {
			return nil, ErrCaptchaRejected
		}
		if rejected != nil || errors.Is(err, ErrSessionInvalid) {
			return nil, ErrLoginRejected
		}
		return nil, fmt.Errorf("login: %w", err)
	}
	var data struct {
		Token string `json:"sid"`
		ID    string `json:"id"`
	}
	if json.Unmarshal(res.Data, &data) != nil {
		return nil, errors.New("invalid gateway login data")
	}
	s := &Session{Username: username, Token: data.Token, UserID: data.ID, Cookie: c.cookie, CreatedAt: time.Now()}
	if s.validate() != nil {
		return nil, errors.New("gateway login response is missing session fields")
	}
	return s, nil
}

// ValidateSession checks the controller API and returns a new session carrying
// any cookie rotation. The input remains unchanged, including on failure.
func (c *Client) ValidateSession(ctx context.Context, session *Session) (*Session, error) {
	c.gatewayDNS = netip.Addr{}
	if session.validate() != nil || session.cookieName() != c.protocol.SessionCookie {
		return nil, ErrSessionInvalid
	}
	c.cookie = session.Cookie
	res, err := c.request(ctx, http.MethodGet, "/user/terminal/rules/"+url.PathEscape(session.UserID), nil)
	if err != nil {
		return nil, fmt.Errorf("validate session: %w", err)
	}
	updated := *session
	updated.Cookie = c.cookie
	if updated.Cookie == "" {
		return nil, errors.New("gateway validation did not retain an authentication cookie")
	}
	c.gatewayDNS = c.policyDNS(res.Data)
	return &updated, nil
}

// RenewSession exchanges a stale session for a fresh one without a captcha.
// The gateway re-keys first and then issues a new token, so the renewed session
// replaces the caller's copy entirely; the input is left untouched.
func (c *Client) RenewSession(ctx context.Context, session *Session) (*Session, error) {
	if session.validate() != nil || session.cookieName() != c.protocol.SessionCookie {
		return nil, ErrSessionInvalid
	}
	if c.protocol.RenewSalt == "" {
		return nil, errors.New("session renewal needs protocol.renew_salt")
	}
	c.cookie = session.Cookie
	if _, err := c.GenerateKey(ctx); err != nil {
		return nil, fmt.Errorf("renew session: %w", err)
	}
	digest := md5.Sum([]byte(session.UserID + c.protocol.RenewSalt))
	payload, err := json.Marshal(struct {
		CheckID string `json:"checkId"`
	}{CheckID: hex.EncodeToString(digest[:])})
	if err != nil {
		return nil, errors.New("cannot encode session renewal request")
	}
	res, err := c.request(ctx, http.MethodPost, "/auth/v2/online/up", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("renew session: %w", err)
	}
	var data struct {
		Token string `json:"sid"`
		ID    string `json:"id"`
	}
	if json.Unmarshal(res.Data, &data) != nil {
		return nil, errors.New("invalid session renewal data")
	}
	renewed := &Session{Username: session.Username, Token: data.Token, UserID: data.ID, Cookie: c.cookie, CreatedAt: time.Now()}
	if renewed.validate() != nil {
		return nil, errors.New("session renewal response is missing session fields")
	}
	return renewed, nil
}

// BindVirtualIP registers the address this connection was assigned. The
// gateway hands out the address, the controller records the lease; leaving the
// controller uninformed desynchronises the two.
func (c *Client) BindVirtualIP(ctx context.Context, session *Session, virtualIP string) error {
	return c.lease(ctx, http.MethodPut, "/user/updateUserSession", session, virtualIP)
}

// ReleaseVirtualIP returns the lease so the controller does not keep an
// address reserved for a connection that has ended.
func (c *Client) ReleaseVirtualIP(ctx context.Context, session *Session, virtualIP string) error {
	return c.lease(ctx, http.MethodPut, "/user/clearVirtualIp", session, virtualIP)
}

func (c *Client) lease(ctx context.Context, method, path string, session *Session, virtualIP string) error {
	if session.validate() != nil || session.cookieName() != c.protocol.SessionCookie {
		return ErrSessionInvalid
	}
	payload, err := json.Marshal(struct {
		SessionID string `json:"sessionId"`
		VirtualIP string `json:"virtualIp"`
		Gateway   string `json:"gateway"`
	}{SessionID: session.Token, VirtualIP: virtualIP, Gateway: c.origin.Hostname()})
	if err != nil {
		return errors.New("cannot encode virtual IP lease request")
	}
	if _, err := c.request(ctx, method, path, bytes.NewReader(payload)); err != nil {
		return fmt.Errorf("virtual IP lease %s: %w", path, err)
	}
	return nil
}

func (c *Client) policyDNS(data json.RawMessage) netip.Addr {
	var policy struct {
		GatewayList []struct {
			IP  string `json:"ip"`
			DNS string `json:"dns"`
		} `json:"gateway_list"`
	}
	if json.Unmarshal(data, &policy) != nil {
		return netip.Addr{}
	}
	for _, gateway := range policy.GatewayList {
		for _, address := range strings.Split(gateway.IP, "||") {
			if !strings.EqualFold(address, c.origin.Host) {
				continue
			}
			ip, err := netip.ParseAddr(gateway.DNS)
			if err == nil && ip.Is4() && ip.IsGlobalUnicast() {
				return ip
			}
		}
	}
	return netip.Addr{}
}
