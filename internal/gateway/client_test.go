package gateway

import (
	"context"
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
	"net/url"
	"strings"
	"testing"
	"time"
)

func testPolicy(tb testing.TB, host string) *tls.Config {
	tb.Helper()
	policy, err := TLSPolicy(host, "")
	if err != nil {
		tb.Fatal(err)
	}
	return policy
}

var testProtocol = Protocol{APIBase: "/gw/api", UserAgent: "TestClient", SessionCookie: "SID"}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testClient(t *testing.T, handler roundTripFunc) *Client {
	t.Helper()
	c, err := NewClient("gateway.invalid", 8443, "", testPolicy(t, "gateway.invalid"), testProtocol)
	if err != nil {
		t.Fatal(err)
	}
	c.httpClient.Transport = handler
	t.Cleanup(c.Close)
	return c
}

func response(status int, body string, cookies ...string) *http.Response {
	resp := &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
	for _, cookie := range cookies {
		resp.Header.Add("Set-Cookie", cookie)
	}
	return resp
}

func testSession() *Session {
	return &Session{
		Username: "alice", Token: "private-fixture-token", UserID: "fixture+&=/alice",
		Cookie: "SID=fixture-session", CreatedAt: time.Unix(1700000000, 0).UTC(),
	}
}

func TestClientRequiresCompleteProtocolProfile(t *testing.T) {
	for _, protocol := range []Protocol{
		{UserAgent: "TestClient", SessionCookie: "SID"},
		{APIBase: "gw/api", UserAgent: "TestClient", SessionCookie: "SID"},
		{APIBase: "/gw/api", SessionCookie: "SID"},
		{APIBase: "/gw/api", UserAgent: "TestClient"},
	} {
		if _, err := NewClient("gateway.invalid", 8443, "", testPolicy(t, "gateway.invalid"), protocol); err == nil {
			t.Fatalf("incomplete protocol accepted: %+v", protocol)
		}
	}
}

func TestValidateSessionRejectsCookieFromAnotherProfile(t *testing.T) {
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("foreign session reached the gateway")
		return nil, nil
	})
	session := testSession()
	session.Cookie = "OTHER=fixture-session"
	if _, err := c.ValidateSession(context.Background(), session); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("foreign cookie session: %v", err)
	}
}

func TestClientSecureDefaultsAndIPv6(t *testing.T) {
	c, err := NewClient("::1", 8443, "127.0.0.1", testPolicy(t, "::1"), testProtocol)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.origin.String() != "https://[::1]:8443" {
		t.Fatal("invalid IPv6 gateway origin")
	}
	transport := c.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 || transport.TLSClientConfig.ServerName != "::1" {
		t.Fatal("unsafe TLS defaults")
	}
	for _, tc := range []struct {
		host string
		port int
		bind string
	}{
		{"", 8443, ""}, {"example.invalid/path", 8443, ""}, {"user@gateway.invalid", 8443, ""},
		{"gateway.invalid", 0, ""}, {"gateway.invalid", 65536, ""}, {"gateway.invalid", 8443, "invalid"},
	} {
		if client, err := NewClient(tc.host, tc.port, tc.bind, testPolicy(t, tc.host), testProtocol); err == nil {
			client.Close()
			t.Fatal("invalid gateway configuration accepted")
		}
	}
}

func TestAuthenticationFlowAndCookieRotation(t *testing.T) {
	var steps []string
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		steps = append(steps, r.URL.Path)
		if r.Header.Get("User-Agent") != "TestClient" || r.Header.Get("Accept") != "application/json" {
			t.Error("missing gateway protocol headers")
		}
		switch r.URL.Path {
		case "/gw/api/auth/generateKey":
			if r.Header.Get("Cookie") != "" {
				t.Error("first request unexpectedly authenticated")
			}
			return response(200, `{"code":"200","data":"aQnaBtkLpMltNdei"}`, "SID=initial; Path=/; Secure", "unrelated=ignored; Path=/"), nil
		case "/gw/api/auth/v2/getCaptcha":
			if r.Header.Get("Cookie") != "SID=initial" {
				t.Error("captcha request did not use the sole authentication cookie")
			}
			return response(200, `{"code":"200","data":"aW1hZ2U="}`, "SID=rotated; Path=/gw"), nil
		case "/gw/api/auth/login":
			if r.Method != http.MethodPost || r.Header.Get("Cookie") != "SID=rotated" {
				t.Error("login did not use the rotated cookie")
			}
			var body struct {
				Username string `json:"username"`
				Password string `json:"password"`
				Code     string `json:"code"`
				Finger   bool   `json:"isFingerPrint"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Password != "ZzG0DAgkkdLtBv7OIOrlDw==" || body.Code != "1234" || body.Username != "alice" || body.Finger {
				t.Error("incorrect encrypted login payload")
			}
			return response(200, `{"code":"200","data":{"sid":"session-token","id":"alice-id"}}`, "SID=logged-in; Path=/"), nil
		default:
			t.Error("unexpected authentication endpoint")
			return response(404, ""), nil
		}
	})
	key, err := c.GenerateKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	image, err := c.GetCaptcha(context.Background())
	if err != nil || string(image) != "image" {
		t.Fatalf("captcha decode failed: %v", err)
	}
	session, err := c.Login(context.Background(), "alice", "TestPass1234", key, "1234")
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 3 || session.Username != "alice" || session.Token != "session-token" || session.UserID != "alice-id" || session.Cookie != "SID=logged-in" || session.CreatedAt.IsZero() {
		t.Fatal("incomplete gateway session")
	}
}

func TestValidateSessionClassificationAndRedaction(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		invalid bool
	}{
		{"unauthorized", 401, "private-fixture-token", true},
		{"forbidden", 403, "private-fixture-token", true},
		{"API unauthorized", 200, `{"code":"401"}`, true},
		{"API forbidden", 200, `{"code":"403"}`, true},
		{"session revoked", 200, `{"code":"1001","messages":"Account was kicked offline by the administrator, please log in again!"}`, true},
		{"server outage", 503, "private-fixture-token", false},
		{"invalid JSON", 200, "private-fixture-token", false},
		{"API error", 200, `{"code":"500","messages":"private-fixture-token"}`, false},
		{"invalid data shape", 200, `{"code":false,"messages":"private-fixture-token"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t, func(*http.Request) (*http.Response, error) {
				return response(tc.status, tc.body), nil
			})
			session := testSession()
			original := *session
			updated, err := c.ValidateSession(context.Background(), session)
			if err == nil || updated != nil || errors.Is(err, ErrSessionInvalid) != tc.invalid {
				t.Fatalf("unexpected rejection classification: %v", err)
			}
			if strings.Contains(err.Error(), session.Token) || *session != original {
				t.Fatal("failure exposed credentials or mutated cached session")
			}
		})
	}
}

func TestValidateSessionImmutableRotationAndEscapedUserID(t *testing.T) {
	session := testSession()
	original := *session
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		want := "/gw/api/user/terminal/rules/" + url.PathEscape(session.UserID)
		if r.URL.EscapedPath() != want || r.Header.Get("Cookie") != session.Cookie {
			t.Error("incorrect session validation request")
		}
		if len(r.Cookies()) != 1 {
			t.Error("duplicate authentication cookies")
		}
		return response(200, `{"code":"200","data":[]}`, "SID=new-session; Path=/"), nil
	})
	updated, err := c.ValidateSession(context.Background(), session)
	if err != nil {
		t.Fatal(err)
	}
	if *session != original || updated == session || updated.Cookie != "SID=new-session" {
		t.Fatal("validation did not return an independent rotated session")
	}
	for _, invalid := range []*Session{nil, {}, {Token: "token"}} {
		if _, err := c.ValidateSession(context.Background(), invalid); !errors.Is(err, ErrSessionInvalid) {
			t.Fatal("incomplete session accepted")
		}
	}
}

func TestNetworkFailureAndCancellationPreserveSession(t *testing.T) {
	sentinel := errors.New("temporary network failure")
	c := testClient(t, func(*http.Request) (*http.Response, error) { return nil, sentinel })
	if _, err := c.ValidateSession(context.Background(), testSession()); !errors.Is(err, sentinel) || errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("network failure misclassified: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		cancel()
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	if _, err := c.ValidateSession(ctx, testSession()); !errors.Is(err, context.Canceled) || errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("cancellation misclassified: %v", err)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	requests := 0
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		requests++
		resp := response(302, "")
		resp.Header.Set("Location", "https://outside.invalid/path?token=private-fixture-token")
		return resp, nil
	})
	_, err := c.ValidateSession(context.Background(), testSession())
	if err == nil || requests != 1 || strings.Contains(err.Error(), "private-fixture-token") {
		t.Fatal("redirect followed or exposed its URL")
	}
}

func TestGenerateKeyChecksStatusLengthAndCookie(t *testing.T) {
	for _, tc := range []struct {
		name, body, cookie string
		ok                 bool
	}{
		{"valid", `{"code":"200","data":"0123456789abcdef"}`, "SID=session", true},
		{"API rejection", `{"code":"500","data":"0123456789abcdef"}`, "SID=session", false},
		{"short key", `{"code":"200","data":"short"}`, "SID=session", false},
		{"AES256 IV mismatch", `{"code":"200","data":"0123456789abcdef0123456789abcdef"}`, "SID=session", false},
		{"invalid type", `{"code":"200","data":42}`, "SID=session", false},
		{"missing cookie", `{"code":"200","data":"0123456789abcdef"}`, "", false},
		{"expired cookie", `{"code":"200","data":"0123456789abcdef"}`, "SID=session; Max-Age=0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t, func(*http.Request) (*http.Response, error) { return response(200, tc.body, tc.cookie), nil })
			_, err := c.GenerateKey(context.Background())
			if (err == nil) != tc.ok {
				t.Fatalf("unexpected key result: %v", err)
			}
		})
	}
}

func TestCaptchaRejectsInvalidAndOversizedData(t *testing.T) {
	for _, data := range []string{`""`, `"!!!"`, `42`, fmt.Sprintf("%q", base64.StdEncoding.EncodeToString(nil))} {
		c := testClient(t, func(*http.Request) (*http.Response, error) {
			return response(200, `{"code":"200","data":`+data+"}"), nil
		})
		if _, err := c.GetCaptcha(context.Background()); err == nil {
			t.Fatal("invalid captcha accepted")
		}
	}
	for _, operation := range []func(*Client) error{
		func(c *Client) error { _, err := c.GenerateKey(context.Background()); return err },
		func(c *Client) error { _, err := c.GetCaptcha(context.Background()); return err },
	} {
		c := testClient(t, func(*http.Request) (*http.Response, error) {
			return response(200, strings.Repeat("x", maxAPIResponse+1)), nil
		})
		if err := operation(c); err == nil || !strings.Contains(err.Error(), "too large") {
			t.Fatalf("oversized response accepted: %v", err)
		}
	}
}

func TestLoginClassifiesCaptchaWithoutLeakingMessages(t *testing.T) {
	for _, message := range []string{"验证码错误 private-password", "Captcha invalid private-password", "password incorrect private-password"} {
		c := testClient(t, func(*http.Request) (*http.Response, error) {
			body, _ := json.Marshal(map[string]string{"code": "500", "messages": message})
			return response(200, string(body)), nil
		})
		_, err := c.Login(context.Background(), "alice", "private-password", "0123456789abcdef", "1234")
		captcha := strings.Contains(message, "验证码") || strings.Contains(message, "Captcha")
		if err == nil || errors.Is(err, ErrCaptchaRejected) != captcha || strings.Contains(err.Error(), "private-password") {
			t.Fatalf("unsafe login rejection: %v", err)
		}
		if errors.Is(err, ErrLoginRejected) == captcha {
			t.Fatal("credential rejection misclassified")
		}
	}
}

func TestLoginRequiresCompleteSession(t *testing.T) {
	for _, tc := range []struct {
		data, cookie string
	}{
		{`{"id":"alice"}`, "SID=session"},
		{`{"sid":"token"}`, "SID=session"},
		{`{"sid":"token","id":"alice"}`, ""},
		{`"private-fixture-token"`, "SID=session"},
	} {
		c := testClient(t, func(*http.Request) (*http.Response, error) {
			return response(200, `{"code":"200","data":`+tc.data+"}", tc.cookie), nil
		})
		if _, err := c.Login(context.Background(), "alice", "password", "0123456789abcdef", "1234"); err == nil {
			t.Fatal("incomplete login accepted")
		}
	}
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid input reached gateway")
		return nil, net.ErrClosed
	})
	for _, fields := range [][4]string{{"", "password", "0123456789abcdef", "1234"}, {"alice", "", "0123456789abcdef", "1234"}, {"alice", "password", "short", "1234"}, {"alice", "password", "0123456789abcdef", ""}} {
		if _, err := c.Login(context.Background(), fields[0], fields[1], fields[2], fields[3]); err == nil {
			t.Fatal("invalid login input accepted")
		}
	}
}

func TestCookieDeletionAndDuplicateRejection(t *testing.T) {
	for _, cookies := range [][]string{
		{"SID=; Max-Age=0"},
		{"SID=first; Path=/", "SID=second; Path=/gw"},
	} {
		c := testClient(t, func(*http.Request) (*http.Response, error) {
			return response(200, `{"code":"200","data":[]}`, cookies...), nil
		})
		if _, err := c.ValidateSession(context.Background(), testSession()); err == nil {
			t.Fatal("deleted or duplicate authentication cookie accepted")
		}
	}
}

func TestGatewayDNSComesFromMatchingAuthenticatedPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, endpoint, dns string
		match               bool
	}{
		{"hostname alias", "gateway.invalid:8443||192.0.2.10", "10.0.0.53", true},
		{"case insensitive hostname", "GATEWAY.INVALID:8443||192.0.2.10", "10.0.0.53", true},
		{"other gateway", "other.invalid:8443||192.0.2.10", "10.0.0.53", false},
		{"other port", "gateway.invalid:443||192.0.2.10", "10.0.0.53", false},
		{"substring domain", "gateway.invalid.attacker:8443", "10.0.0.53", false},
		{"invalid DNS", "gateway.invalid:8443", "not-an-ip", false},
		{"IPv6 DNS", "gateway.invalid:8443", "2001:db8::53", false},
		{"unspecified DNS", "gateway.invalid:8443", "0.0.0.0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t, func(*http.Request) (*http.Response, error) {
				body, _ := json.Marshal(map[string]any{"code": "200", "data": map[string]any{"gateway_list": []map[string]string{{"ip": tc.endpoint, "dns": tc.dns}}}})
				return response(200, string(body)), nil
			})
			if _, err := c.ValidateSession(context.Background(), testSession()); err != nil {
				t.Fatal(err)
			}
			if c.GatewayDNS().IsValid() != tc.match {
				t.Fatalf("unexpected gateway DNS match: %v", c.GatewayDNS())
			}
			if tc.match && c.GatewayDNS().String() != tc.dns {
				t.Fatal("selected a different DNS server")
			}
		})
	}
}

func TestGatewayDNSClearedBeforeEachValidation(t *testing.T) {
	responses := []string{
		`{"code":"200","data":{"gateway_list":[{"ip":"gateway.invalid:8443||192.0.2.10","dns":"10.0.0.53"}]}}`,
		`{"code":"200","data":[]}`,
		`{"code":"200","data":{"gateway_list":[{"ip":"gateway.invalid:8443","dns":"10.0.0.53"}]}}`,
		`{"code":"401"}`,
	}
	index := 0
	c := testClient(t, func(*http.Request) (*http.Response, error) {
		body := responses[index]
		index++
		return response(200, body), nil
	})
	for i := range responses {
		_, err := c.ValidateSession(context.Background(), testSession())
		if i == 3 && !errors.Is(err, ErrSessionInvalid) {
			t.Fatal("authentication rejection lost")
		}
		want := i == 0 || i == 2
		if c.GatewayDNS().IsValid() != want {
			t.Fatal("revalidation retained stale gateway DNS")
		}
	}
}

func TestGatewayDNSMatchesConfiguredIPAddressAlias(t *testing.T) {
	c, err := NewClient("192.0.2.10", 8443, "", testPolicy(t, "192.0.2.10"), testProtocol)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(200, `{"code":"200","data":{"gateway_list":[{"ip":"gateway.invalid:8443||192.0.2.10:8443||443","dns":"10.0.0.53"}]}}`), nil
	})
	if _, err = c.ValidateSession(context.Background(), testSession()); err != nil {
		t.Fatal(err)
	}
	if c.GatewayDNS().String() != "10.0.0.53" {
		t.Fatal("configured IP did not match gateway alias")
	}
}

func TestRenewSessionRekeysAndAdoptsTheNewToken(t *testing.T) {
	stale := testSession()
	protocol := testProtocol
	protocol.RenewSalt = "test-salt"
	c, err := NewClient("gateway.invalid", 8443, "", testPolicy(t, "gateway.invalid"), protocol)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var steps []string
	var body []byte
	c.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		steps = append(steps, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/gw/api/auth/generateKey":
			if r.Header.Get("Cookie") != stale.Cookie {
				t.Fatalf("renewal must present the stale cookie, got %q", r.Header.Get("Cookie"))
			}
			return response(200, `{"code":"200","data":"0123456789abcdef"}`, "SID=rekeyed"), nil
		case "/gw/api/auth/v2/online/up":
			if r.Header.Get("Cookie") != "SID=rekeyed" {
				t.Fatalf("renewal must use the re-keyed cookie, got %q", r.Header.Get("Cookie"))
			}
			body, _ = io.ReadAll(r.Body)
			return response(200, `{"code":"200","messages":"OK","data":{"sid":"renewed-token","id":"renewed-id"}}`, "SID=renewed"), nil
		}
		t.Fatalf("unexpected request %s", r.URL.Path)
		return nil, nil
	})

	renewed, err := c.RenewSession(context.Background(), stale)
	if err != nil {
		t.Fatalf("renew session: %v", err)
	}
	// The gateway re-keys before issuing a token; the order is part of the protocol.
	if len(steps) != 2 || steps[0] != "GET /gw/api/auth/generateKey" || steps[1] != "POST /gw/api/auth/v2/online/up" {
		t.Fatalf("unexpected renewal sequence: %v", steps)
	}
	var payload struct {
		CheckID string `json:"checkId"`
	}
	if json.Unmarshal(body, &payload) != nil {
		t.Fatalf("invalid renewal body: %s", body)
	}
	digest := md5.Sum([]byte(stale.UserID + "test-salt"))
	if payload.CheckID != hex.EncodeToString(digest[:]) {
		t.Fatalf("checkId must be the lowercase hex md5 of user id plus salt, got %q", payload.CheckID)
	}
	if renewed.Token != "renewed-token" || renewed.UserID != "renewed-id" || renewed.Cookie != "SID=renewed" {
		t.Fatalf("renewal must replace the token, user id and cookie: %+v", renewed)
	}
	if *stale != *testSession() {
		t.Fatal("renewal mutated the caller's session")
	}
}

func TestRenewSessionRequiresSaltAndValidSession(t *testing.T) {
	noSalt := testClient(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("renewal without a salt must not reach the gateway")
		return nil, nil
	})
	if _, err := noSalt.RenewSession(context.Background(), testSession()); err == nil {
		t.Fatal("renewal without protocol.renew_salt accepted")
	}

	protocol := testProtocol
	protocol.RenewSalt = "test-salt"
	c, err := NewClient("gateway.invalid", 8443, "", testPolicy(t, "gateway.invalid"), protocol)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("an invalid session must not reach the gateway")
		return nil, nil
	})
	if _, err := c.RenewSession(context.Background(), &Session{Username: "alice"}); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("expected ErrSessionInvalid, got %v", err)
	}
}

func TestBindVirtualIP(t *testing.T) {
	s := testSession()
	var gotPath string
	var gotMethod string
	var gotBody []byte
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotBody, _ = io.ReadAll(r.Body)
		return response(200, `{"code":"200","messages":"OK","data":null}`), nil
	})
	if err := c.BindVirtualIP(context.Background(), s, "1.1.4.157"); err != nil {
		t.Fatalf("bind virtual ip failed: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Fatalf("expected PUT, got %s", gotMethod)
	}
	if gotPath != "/gw/api/user/updateUserSession" {
		t.Fatalf("expected /gw/api/user/updateUserSession, got %s", gotPath)
	}
	var payload struct {
		SessionID string `json:"sessionId"`
		VirtualIP string `json:"virtualIp"`
		Gateway   string `json:"gateway"`
	}
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("invalid json body: %v", err)
	}
	if payload.SessionID != s.Token || payload.VirtualIP != "1.1.4.157" || payload.Gateway != "gateway.invalid" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestReleaseVirtualIPClosesTheLease(t *testing.T) {
	s := testSession()
	var gotPath, gotMethod string
	c := testClient(t, func(r *http.Request) (*http.Response, error) {
		gotPath, gotMethod = r.URL.Path, r.Method
		return response(200, `{"code":"200","messages":"OK","data":null}`), nil
	})
	if err := c.ReleaseVirtualIP(context.Background(), s, "1.1.4.157"); err != nil {
		t.Fatalf("release virtual ip: %v", err)
	}
	if gotMethod != http.MethodPut || gotPath != "/gw/api/user/clearVirtualIp" {
		t.Fatalf("unexpected lease release %s %s", gotMethod, gotPath)
	}
}

// A policy built for one gateway must not be handed to a client that talks to
// another: the certificate would be verified against the wrong name.
func TestClientRejectsAPolicyForAnotherGateway(t *testing.T) {
	if _, err := NewClient("gateway.invalid", 8443, "", testPolicy(t, "other.invalid"), testProtocol); err == nil {
		t.Fatal("a TLS policy for a different gateway was accepted")
	}
}
