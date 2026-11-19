// Package account manages Xiaomi account authentication, OTP verification,
// token persistence, and authenticated service requests.
package account

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	AccountBase      = "https://account.xiaomi.com"
	UALogin          = "APP/com.xiaomi.mihome APPV/11.3.203 iosPassportSDK/4.2.50 iOS/26.3.1 MK/aVBob25lMTcsMg== DEVT/aVBob25l DEVS/aU9T BRA/QXBwbGU= L/zh_CN"
	UAOTP            = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 iOS/26.3.1 MiHome/11.3.203 iPhone/iPhone17,2 DeviceId/%s APP/com.xiaomi.mihome APPV/11.3.203 Platform/iPhone Region/CN /xiaomi/miuibrowser/4.3/smartHome/ios/iPhone17,2/11.3.203 " + UALogin
	DefaultTokenPath = ".mi.token"
	loginCooldown    = 2 * time.Hour
	loginRetryMax    = 5
	loginRateCode    = 70022
)

// APIError represents an HTTP or business-level error returned by a Xiaomi service.
type APIError struct {
	HTTPStatus int
	Code       int
	Message    string
}

func (e *APIError) Error() string {
	if e.HTTPStatus != 0 && e.HTTPStatus != http.StatusOK {
		return fmt.Sprintf("Xiaomi service HTTP %d", e.HTTPStatus)
	}
	if e.Message != "" {
		return fmt.Sprintf("Xiaomi service request failed (code=%d): %s", e.Code, e.Message)
	}
	return fmt.Sprintf("Xiaomi service request failed (code=%d)", e.Code)
}

var (
	ErrOTPRequired      = errors.New("Xiaomi login requires OTP verification")
	ErrLoginRateLimited = errors.New("Xiaomi login is rate limited")
)

// OTPCallback supplies the code for the selected method ("Phone" or "Email").
type OTPCallback func(context.Context, string) (string, error)

// TokenStore loads and saves account state. A nil token clears stored state.
type TokenStore interface {
	LoadToken(context.Context) (*MiToken, error)
	SaveToken(context.Context, *MiToken) error
}

type ServiceToken struct {
	SSecurity, ServiceToken string
}

type MiToken struct {
	Username, DeviceID, PassToken string
	UserID                        any
	Services                      map[string]ServiceToken
}

// MarshalJSON uses the MiService token file format, with a service pair per SID.
func (t MiToken) MarshalJSON() ([]byte, error) {
	fields := make(map[string]any, len(t.Services)+4)
	for sid, svc := range t.Services {
		fields[sid] = [2]string{svc.SSecurity, svc.ServiceToken}
	}
	fields["deviceId"], fields["userId"], fields["passToken"] = t.DeviceID, t.UserID, t.PassToken
	if t.Username != "" {
		fields["username"] = t.Username
	}
	return json.Marshal(fields)
}

func (t *MiToken) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	out := MiToken{Services: make(map[string]ServiceToken)}
	for key, raw := range fields {
		var dst any
		switch key {
		case "username":
			dst = &out.Username
		case "deviceId":
			dst = &out.DeviceID
		case "userId":
			dst = &out.UserID
		case "passToken":
			dst = &out.PassToken
		default:
			var pair []string
			if json.Unmarshal(raw, &pair) == nil && len(pair) == 2 {
				out.Services[key] = ServiceToken{pair[0], pair[1]}
			}
			continue
		}
		if err := DecodeJSON(raw, dst); err != nil {
			return err
		}
	}
	*t = out
	return nil
}

// FileTokenStore writes MiService-compatible JSON files atomically with mode 0600.
type FileTokenStore struct{ Path string }

func (s FileTokenStore) LoadToken(ctx context.Context) (*MiToken, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var t MiToken
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func (s FileTokenStore) SaveToken(ctx context.Context, t *MiToken) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if t == nil {
		err := os.Remove(s.Path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.Path), ".mi-token-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	writeErr := encoder.Encode(t)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return err
	}
	return os.Rename(f.Name(), s.Path)
}

type Option func(*MiAccount)

func WithHTTPClient(client *http.Client) Option {
	return func(a *MiAccount) { a.client = client }
}

func WithTokenStore(store TokenStore) Option {
	return func(a *MiAccount) { a.store = store }
}

// WithTokenPath selects the token file, or disables persistence when path is empty.
func WithTokenPath(path string) Option {
	if path == "" {
		return WithTokenStore(nil)
	}
	return WithTokenStore(FileTokenStore{Path: path})
}

func WithOTPCallback(callback OTPCallback) Option {
	return func(a *MiAccount) { a.otp = callback }
}

func WithLogger(logger *slog.Logger) Option {
	return func(a *MiAccount) { a.logger = logger }
}

// MiAccount authorizes requests to Xiaomi services and shares the login across SIDs.
// By default, OTP verification is disabled (returns ErrOTPRequired) so non-interactive
// services never block on stdin; pass WithOTPCallback to handle 2FA interactively.
type MiAccount struct {
	username, password string
	client             *http.Client
	ownsClient         bool
	store              TokenStore
	otp                OTPCallback
	logger             *slog.Logger
	gate               chan struct{}
	loaded             bool
	token              *MiToken
	failures           int
	cooldownUntil      time.Time
}

// New creates a MiAccount with FileTokenStore(".mi.token") and no interactive OTP callback.
func New(username, password string, options ...Option) *MiAccount {
	a := &MiAccount{
		username: username, password: password, store: FileTokenStore{Path: DefaultTokenPath},
		logger: slog.Default(), gate: make(chan struct{}, 1),
	}
	for _, option := range options {
		option(a)
	}
	if a.client == nil {
		jar, _ := cookiejar.New(nil)
		a.client = &http.Client{Timeout: 30 * time.Second, Jar: jar}
		a.ownsClient = true
	}
	return a
}

func (a *MiAccount) Close() error {
	if a.ownsClient {
		a.client.CloseIdleConnections()
	}
	return nil
}

// RandomString returns an alphanumeric string sampled without replacement.
func RandomString(length int) (string, error) {
	pool := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	if length < 0 || length > len(pool) {
		return "", errors.New("invalid random string length")
	}
	for i := 0; i < length; i++ {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(len(pool)-i)))
		if err != nil {
			return "", err
		}
		k := i + int(j.Int64())
		pool[i], pool[k] = pool[k], pool[i]
	}
	return string(pool[:length]), nil
}

// DecodeJSON decodes a single JSON value using json.Number and rejects trailing bytes.
func DecodeJSON(b []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF {
		return errors.New("unexpected data after JSON response")
	}
	return nil
}

// String converts a JSON scalar (string, json.Number, or integer) to a string.
func String(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case json.Number:
		return string(v)
	case int, int64, uint64:
		return fmt.Sprint(v)
	}
	return ""
}

func validServiceToken(sid string, token ServiceToken) bool {
	if token.ServiceToken == "" || token.SSecurity == "" {
		return false
	}
	if sid == "xiaomiio" {
		secret, err := base64.StdEncoding.DecodeString(token.SSecurity)
		return err == nil && len(secret) != 0
	}
	return true
}

// IsZeroCode reports whether a Xiaomi API code value equals zero.
func IsZeroCode(v any) bool {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return err == nil && f == 0
	case bool:
		return !n // Python considers False equal to 0.
	default:
		return false
	}
}

func accountCode(code *int) int {
	if code == nil {
		return -1
	}
	return *code
}

func readAccountBody(resp *http.Response) ([]byte, error) {
	const max = 16 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if len(body) > max {
		return nil, errors.New("Xiaomi HTTP response exceeds 16 MiB")
	}
	return body, err
}

func accountRequest(ctx context.Context, method, address string, body io.Reader, headers http.Header) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, address, body)
	if err != nil {
		return nil, errors.New("invalid Xiaomi HTTP request")
	}
	if headers != nil {
		req.Header = headers.Clone()
	}
	return req, nil
}

func accountFormRequest(ctx context.Context, address string, form url.Values, headers http.Header) (*http.Request, error) {
	method := http.MethodGet
	var body io.Reader
	if form != nil {
		method, body = http.MethodPost, strings.NewReader(form.Encode())
	}
	req, err := accountRequest(ctx, method, address, body, headers)
	if err == nil && form != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return req, err
}

func doAccountHTTP(client *http.Client, req *http.Request) (*http.Response, error) {
	resp, err := client.Do(req)
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		// The URL can carry login credentials, e.g. the STS query.
		if errors.Is(err, context.Canceled) {
			return nil, context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, context.DeadlineExceeded
		}
		return nil, fmt.Errorf("Xiaomi HTTP transport failed: %w", urlErr.Err)
	}
	return resp, err
}

// Request performs a plain HTTP request without obtaining a service token.
// The caller must close the response body.
func (a *MiAccount) Request(ctx context.Context, method, address string, body io.Reader, headers http.Header) (*http.Response, error) {
	req, err := accountRequest(ctx, method, address, body, headers)
	if err != nil {
		return nil, err
	}
	return doAccountHTTP(a.client, req)
}

func (a *MiAccount) log(ctx context.Context, level slog.Level, message string, args ...any) {
	if a.logger != nil {
		a.logger.Log(ctx, level, message, args...)
	}
}

func (a *MiAccount) persist(ctx context.Context, token *MiToken) {
	if a.store != nil && a.store.SaveToken(ctx, token) != nil {
		a.log(ctx, slog.LevelWarn, "Could not update Xiaomi token cache")
	}
}

func sameServiceToken(a, b *MiToken, sid string) bool {
	return a != nil && b != nil && String(a.UserID) == String(b.UserID) && a.Services[sid] == b.Services[sid]
}

func withoutServiceToken(old *MiToken, sid string) *MiToken {
	token := *old
	token.Services = maps.Clone(old.Services)
	delete(token.Services, sid)
	// Do not reuse a passToken from a service session that was rejected.
	token.PassToken = ""
	return &token
}

func (a *MiAccount) session(ctx context.Context, sid string, rejected *MiToken) (*MiToken, error) {
	if sid == "" || sid == "deviceId" || sid == "userId" || sid == "passToken" || sid == "username" {
		return nil, errors.New("invalid Xiaomi service ID")
	}
	select {
	case a.gate <- struct{}{}:
		defer func() { <-a.gate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !a.loaded && a.store != nil {
		token, err := a.store.LoadToken(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			a.log(ctx, slog.LevelWarn, "Could not load Xiaomi token cache")
		} else if token != nil && token.DeviceID != "" && String(token.UserID) != "" && (token.Username == "" || a.username == "" || a.username == token.Username) {
			a.token = token
		}
		a.loaded = true
	}
	if rejected != nil && sameServiceToken(a.token, rejected, sid) {
		a.token = withoutServiceToken(a.token, sid)
		if len(a.token.Services) == 0 {
			a.token = nil
		}
		if a.store != nil {
			stored, err := a.store.LoadToken(ctx)
			if err == nil && sameServiceToken(stored, rejected, sid) {
				cleaned := withoutServiceToken(stored, sid)
				if len(cleaned.Services) == 0 {
					cleaned = nil
				}
				a.persist(ctx, cleaned)
			}
		}
	}
	if a.token != nil && validServiceToken(sid, a.token.Services[sid]) {
		return a.token, nil
	}
	if a.failures >= loginRetryMax {
		if remaining := time.Until(a.cooldownUntil); remaining > 0 {
			return nil, fmt.Errorf("%w; retry in %s", ErrLoginRateLimited, remaining.Round(time.Second))
		}
		a.failures = 0
	}
	a.log(ctx, slog.LevelDebug, "Starting Xiaomi service login", "sid", sid)
	token, err := a.login(ctx, sid, rejected != nil)
	if errors.Is(err, ErrLoginRateLimited) {
		a.failures++
		if a.failures == loginRetryMax {
			a.cooldownUntil = time.Now().Add(loginCooldown)
		}
	} else {
		a.failures = 0
	}
	if err != nil {
		return nil, err
	}
	a.token = token
	a.persist(ctx, token)
	a.log(ctx, slog.LevelInfo, "Xiaomi service login succeeded", "sid", sid)
	return token, nil
}

// Login ensures there is a service token for sid, reusing a stored token when possible.
func (a *MiAccount) Login(ctx context.Context, sid string) error {
	_, err := a.session(ctx, sid, nil)
	return err
}

type accountLoginReply struct {
	Code                *int
	QS, SID             string
	Sign                string `json:"_sign"`
	Callback            string
	UserID              any
	PassToken, Location string
	Nonce               any
	SSecurity           string
	Notification        string `json:"notificationUrl"`
	Captcha             string `json:"captchaUrl"`
}

func isXiaomiHTTPS(u *url.URL) bool {
	return u.Scheme == "https" && u.User == nil && (u.Port() == "" || u.Port() == "443")
}

func trustedServiceURL(u *url.URL) bool {
	host := u.Hostname()
	return isXiaomiHTTPS(u) && (host == "api.io.mi.com" || strings.HasSuffix(host, ".api.io.mi.com") ||
		host == "mina.mi.com" || strings.HasSuffix(host, ".mina.mi.com"))
}

func trustedLoginURL(u *url.URL) bool {
	host := u.Hostname()
	return trustedServiceURL(u) || isXiaomiHTTPS(u) &&
		(host == "account.xiaomi.com" || host == "sts.mi.com" || host == "sts.xiaomi.com")
}

func resolveLoginURL(base *url.URL, address string) (*url.URL, error) {
	u, err := base.Parse(address)
	if address == "" || err != nil || !trustedLoginURL(u) {
		return nil, errors.New("invalid Xiaomi login URL")
	}
	return u, nil
}

func accountLoginJSON(resp *http.Response, dst any) error {
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Xiaomi login HTTP %d", resp.StatusCode)
	}
	b, err := readAccountBody(resp)
	if err != nil {
		return err
	}
	b = bytes.TrimPrefix(b, []byte("&&&START&&&"))
	if len(bytes.TrimSpace(b)) == 0 {
		return nil
	}
	if DecodeJSON(b, dst) != nil {
		return errors.New("invalid Xiaomi login JSON response")
	}
	return nil
}

func (a *MiAccount) login(ctx context.Context, sid string, fresh bool) (*MiToken, error) {
	base, _ := url.Parse(AccountBase)
	t := &MiToken{Services: make(map[string]ServiceToken)}
	if cached := a.token; cached != nil {
		t.Username = cached.Username
		for k, v := range cached.Services {
			t.Services[k] = v
		}
		// Keep the device identity when another service still depends on it.
		if !fresh || len(t.Services) != 0 {
			t.DeviceID = cached.DeviceID
		}
		if !fresh {
			t.UserID, t.PassToken = cached.UserID, cached.PassToken
		}
	}
	if t.PassToken == "" && (a.username == "" || a.password == "") {
		return nil, errors.New("Xiaomi login requires a username and password")
	}
	if t.DeviceID == "" {
		id, err := RandomString(16)
		if err != nil {
			return nil, err
		}
		t.DeviceID = strings.ToUpper(id)
	}

	client := *a.client
	client.Jar, _ = cookiejar.New(nil)
	var serviceToken string
	capture := func(resp *http.Response) {
		for _, c := range resp.Cookies() {
			if c.Name == "serviceToken" && c.Value != "" && c.MaxAge >= 0 {
				serviceToken = c.Value
			}
		}
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 || !trustedLoginURL(req.URL) {
			return errors.New("refusing Xiaomi login redirect")
		}
		if req.URL.Host != via[0].URL.Host {
			req.Header.Del("Cookie")
			if req.Method != http.MethodGet && req.Method != http.MethodHead {
				return errors.New("refusing cross-origin Xiaomi login form redirect")
			}
		}
		req.Header.Del("Referer")
		capture(req.Response)
		if a.client.CheckRedirect != nil {
			return a.client.CheckRedirect(req, via)
		}
		return nil
	}
	start := "serviceLogin?" + (url.Values{"sid": {sid}, "_json": {"true"}}).Encode()
	login := func(path string, form url.Values) (accountLoginReply, error) {
		var result accountLoginReply
		req, err := accountFormRequest(ctx, AccountBase+"/pass/"+path, form, http.Header{"User-Agent": {UALogin}})
		if err != nil {
			return result, err
		}
		req.AddCookie(&http.Cookie{Name: "sdkVersion", Value: "3.9"})
		req.AddCookie(&http.Cookie{Name: "deviceId", Value: t.DeviceID})
		// A completed OTP exchange may have issued a newer login cookie.
		if t.PassToken != "" {
			fresh := false
			for _, c := range client.Jar.Cookies(req.URL) {
				fresh = fresh || c.Name == "passToken"
			}
			if !fresh {
				req.AddCookie(&http.Cookie{Name: "userId", Value: String(t.UserID)})
				req.AddCookie(&http.Cookie{Name: "passToken", Value: t.PassToken})
			}
		}
		resp, err := doAccountHTTP(&client, req)
		if err != nil {
			return result, err
		}
		defer resp.Body.Close()
		err = accountLoginJSON(resp, &result)
		return result, err
	}

	r, err := login(start, nil)
	if err != nil {
		return nil, err
	}
	if accountCode(r.Code) == loginRateCode {
		return nil, ErrLoginRateLimited
	}
	if accountCode(r.Code) != 0 && r.Notification == "" && r.Captcha == "" {
		if a.username == "" || a.password == "" {
			return nil, errors.New("Xiaomi login requires a username and password")
		}
		if r.QS == "" || r.SID != sid || r.Sign == "" || r.Callback == "" {
			return nil, fmt.Errorf("Xiaomi login missing authentication parameters (code=%d)", accountCode(r.Code))
		}
		hash := md5.Sum([]byte(a.password))
		r, err = login("serviceLoginAuth2", url.Values{
			"_json": {"true"}, "qs": {r.QS}, "sid": {r.SID}, "_sign": {r.Sign}, "callback": {r.Callback},
			"user": {a.username}, "hash": {strings.ToUpper(hex.EncodeToString(hash[:]))},
		})
		if err != nil {
			return nil, err
		}
		t.Username = a.username
	}
	if accountCode(r.Code) == loginRateCode {
		return nil, ErrLoginRateLimited
	}
	if r.Captcha != "" {
		return nil, errors.New("Xiaomi login requires a graphical captcha")
	}
	if r.Notification != "" {
		verified, err := a.verifyOTP(ctx, &client, base, t.DeviceID, sid, r.Notification)
		if err != nil {
			return nil, err
		}
		r, err = login(start, nil)
		if err != nil {
			return nil, err
		}
		if accountCode(r.Code) == loginRateCode {
			return nil, ErrLoginRateLimited
		}
		if accountCode(r.Code) != 0 && verified.SSecurity != "" && verified.PassToken != "" && accountCode(verified.Code) == 0 {
			r = verified
		}
		if r.Notification != "" || r.Captcha != "" || accountCode(r.Code) != 0 {
			return nil, fmt.Errorf("Xiaomi login did not resume after OTP (code=%d)", accountCode(r.Code))
		}
	}
	if accountCode(r.Code) != 0 {
		return nil, fmt.Errorf("Xiaomi login failed (code=%d)", accountCode(r.Code))
	}
	if String(r.UserID) == "" || String(r.Nonce) == "" || r.PassToken == "" || r.SSecurity == "" {
		return nil, errors.New("Xiaomi login response is missing token parameters")
	}
	location, err := resolveLoginURL(base, r.Location)
	if err != nil {
		return nil, err
	}
	sign := sha1.Sum([]byte("nonce=" + String(r.Nonce) + "&" + r.SSecurity))
	if location.RawQuery != "" {
		location.RawQuery += "&"
	}
	location.RawQuery += "clientSign=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sign[:]))
	req, err := accountFormRequest(ctx, location.String(), nil, nil)
	if err != nil {
		return nil, err
	}
	serviceToken = ""
	resp, err := doAccountHTTP(&client, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	capture(resp)
	if serviceToken == "" {
		return nil, fmt.Errorf("Xiaomi STS did not return serviceToken (HTTP %d)", resp.StatusCode)
	}
	svc := ServiceToken{r.SSecurity, serviceToken}
	if !validServiceToken(sid, svc) {
		return nil, errors.New("Xiaomi login returned invalid service credentials")
	}
	if a.token != nil && String(a.token.UserID) != String(r.UserID) {
		clear(t.Services)
	}
	t.UserID, t.PassToken = r.UserID, r.PassToken
	t.Services[sid] = svc
	return t, nil
}

func (a *MiAccount) verifyOTP(ctx context.Context, client *http.Client, base *url.URL, deviceID, sid, notification string) (accountLoginReply, error) {
	var verified accountLoginReply
	if a.otp == nil {
		return verified, ErrOTPRequired
	}
	challenge, err := resolveLoginURL(base, notification)
	if err != nil || challenge.Hostname() != base.Hostname() {
		return verified, errors.New("invalid Xiaomi OTP challenge URL")
	}
	open := func(u *url.URL, form url.Values, dst any) (*url.URL, error) {
		req, err := accountFormRequest(ctx, u.String(), form, http.Header{"User-Agent": {fmt.Sprintf(UAOTP, deviceID)}})
		if err != nil {
			return nil, err
		}
		if u.Host == base.Host {
			req.AddCookie(&http.Cookie{Name: "deviceId", Value: deviceID})
		}
		resp, err := doAccountHTTP(client, req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if dst != nil {
			return resp.Request.URL, accountLoginJSON(resp, dst)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			return nil, fmt.Errorf("Xiaomi OTP HTTP %d", resp.StatusCode)
		}
		_, err = readAccountBody(resp)
		return resp.Request.URL, err
	}
	a.log(ctx, slog.LevelInfo, "Xiaomi login requires OTP verification")
	if _, err := open(challenge, nil, nil); err != nil {
		return verified, err
	}
	query := challenge.Query()
	if value := query.Get("sid"); value != "" {
		sid = value
	}
	identityURL := func(path string, query url.Values) *url.URL {
		return &url.URL{Scheme: base.Scheme, Host: base.Host, Path: path, RawQuery: query.Encode()}
	}
	var available struct {
		Code *int
		Flag int
	}
	if _, err := open(identityURL("/identity/list", url.Values{
		"sid": {sid}, "supportedMask": {"0"}, "_locale": {"zh_CN"}, "context": {query.Get("context")},
	}), nil, &available); err != nil {
		return verified, err
	}
	if code := accountCode(available.Code); available.Flag == 0 && code != -1 && code != 0 && code != 2 {
		return verified, fmt.Errorf("cannot get Xiaomi OTP methods (code=%d)", code)
	}
	method, flag := "Phone", "4"
	switch available.Flag {
	case 0, 4:
	case 8:
		method, flag = "Email", "8"
	default:
		return verified, fmt.Errorf("unsupported Xiaomi OTP method (flag=%d)", available.Flag)
	}
	path := "/identity/auth/verify" + method
	send := func(u *url.URL, form url.Values) error {
		var r accountLoginReply
		if _, err := open(u, form, &r); err != nil {
			return err
		}
		if r.Captcha != "" {
			return errors.New("sending Xiaomi OTP requires a graphical captcha")
		}
		if r.Code != nil && *r.Code != 0 {
			return fmt.Errorf("cannot send Xiaomi OTP (code=%d)", *r.Code)
		}
		return nil
	}
	if err := send(identityURL(path, url.Values{"_flag": {flag}, "_json": {"true"}}), nil); err != nil {
		return verified, err
	}
	if method == "Phone" {
		if err := send(identityURL("/identity/auth/sendPhoneTicket", nil), url.Values{"retry": {"0"}, "icode": {""}, "_json": {"true"}}); err != nil {
			return verified, err
		}
	}
	code, err := a.otp(ctx, method)
	if err != nil {
		return verified, err
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return verified, errors.New("no Xiaomi OTP code provided")
	}
	verify := identityURL(path, url.Values{"_dc": {fmt.Sprint(time.Now().UnixMilli())}})
	if _, err := open(verify, url.Values{"_flag": {flag}, "ticket": {code}, "trust": {"false"}, "_json": {"true"}}, &verified); err != nil {
		return verified, err
	}
	if verified.Location == "" {
		return verified, fmt.Errorf("Xiaomi OTP verification did not return a continuation URL (code=%d)", accountCode(verified.Code))
	}
	if verified.SSecurity != "" && verified.PassToken != "" {
		return verified, nil
	}
	location, err := resolveLoginURL(base, verified.Location)
	if err != nil {
		return verified, err
	}
	final, err := open(location, nil, nil)
	if err != nil {
		return verified, err
	}
	if confirm := final.Query().Get("confirmUrl"); confirm != "" {
		u, err := resolveLoginURL(final, confirm)
		if err != nil {
			return verified, err
		}
		if _, err := open(u, nil, nil); err != nil {
			return verified, err
		}
	}
	return verified, nil
}

// MiRequest performs a request to a Xiaomi MiIO or MiNA HTTPS endpoint,
// retrying once with fresh credentials if the service rejects the token.
// A nil form selects GET; otherwise it uses POST.
func (a *MiAccount) MiRequest(ctx context.Context, sid, address string, form url.Values, headers http.Header) (map[string]any, error) {
	return a.MiRequestWith(ctx, sid, address, headers, true, func(MiRequestSession) (url.Values, []*http.Cookie, error) {
		return form, nil, nil
	})
}

// MiRequestSession contains the values needed to sign a Xiaomi service request.
// It does not expose the account's passToken or any service authentication cookie.
type MiRequestSession struct {
	DeviceID  string
	UserID    string
	SSecurity string
}

// MiRequestWith prepares a signed request and optional extra cookies. It calls
// prepare again with the fresh session if retryAuth is true and login is retried.
// A nil form selects GET; a non-nil form selects POST.
func (a *MiAccount) MiRequestWith(ctx context.Context, sid, address string, headers http.Header, retryAuth bool, prepare func(MiRequestSession) (url.Values, []*http.Cookie, error)) (map[string]any, error) {
	if prepare == nil {
		return nil, errors.New("missing Xiaomi request preparation callback")
	}
	u, err := url.Parse(address)
	if err != nil || !trustedServiceURL(u) {
		return nil, errors.New("invalid Xiaomi service URL")
	}
	var rejected *MiToken
	client := *a.client
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many Xiaomi service redirects")
		}
		if origin := via[0].URL; req.URL.Scheme != origin.Scheme || req.URL.Host != origin.Host {
			return http.ErrUseLastResponse
		}
		if a.client.CheckRedirect != nil {
			return a.client.CheckRedirect(req, via)
		}
		return nil
	}
	for attempt := 0; attempt < 2; attempt++ {
		t, err := a.session(ctx, sid, rejected)
		if err != nil {
			return nil, err
		}
		form, cookies, err := prepare(MiRequestSession{t.DeviceID, String(t.UserID), t.Services[sid].SSecurity})
		if err != nil {
			return nil, err
		}
		req, err := accountFormRequest(ctx, address, form, headers)
		if err != nil {
			return nil, err
		}
		// Rebuild the Cookie header so extras cannot shadow the session identity.
		extra := req.Cookies()
		req.Header.Del("Cookie")
		req.AddCookie(&http.Cookie{Name: "userId", Value: String(t.UserID)})
		req.AddCookie(&http.Cookie{Name: "serviceToken", Value: t.Services[sid].ServiceToken})
		addExtra := func(c *http.Cookie) {
			if c != nil && !strings.EqualFold(c.Name, "userId") && !strings.EqualFold(c.Name, "serviceToken") {
				req.AddCookie(c)
			}
		}
		for _, c := range extra {
			addExtra(c)
		}
		for _, c := range cookies {
			addExtra(c)
		}
		resp, err := doAccountHTTP(&client, req)
		if err != nil {
			return nil, err
		}
		status := resp.StatusCode
		auth := status == http.StatusUnauthorized
		if status != http.StatusOK {
			resp.Body.Close()
			err = &APIError{HTTPStatus: status}
		} else {
			body, readErr := readAccountBody(resp)
			resp.Body.Close()
			if readErr != nil {
				return nil, readErr
			}
			var result map[string]any
			if DecodeJSON(body, &result) != nil {
				return nil, errors.New("invalid Xiaomi service JSON response")
			}
			if IsZeroCode(result["code"]) {
				return result, nil
			}
			message, _ := result["message"].(string)
			auth = strings.Contains(strings.ToLower(message), "auth")
			code := -1
			if n, ok := result["code"].(json.Number); ok {
				if parsed, convErr := strconv.Atoi(string(n)); convErr == nil {
					code = parsed
				}
			}
			err = &APIError{HTTPStatus: status, Code: code, Message: message}
		}
		if !retryAuth || !auth || attempt == 1 {
			return nil, err
		}
		a.log(ctx, slog.LevelWarn, "Xiaomi service rejected token; retrying login", "sid", sid)
		rejected = t
	}
	panic("unreachable")
}
