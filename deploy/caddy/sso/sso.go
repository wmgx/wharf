package sso

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const CLOCK_SKEW = 30
const takeoverCookie = "wharf_takeover"

func init() {
	caddy.RegisterModule(SSO{})
	httpcaddyfile.RegisterHandlerDirective("wharf_sso", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		var s SSO
		return &s, s.UnmarshalCaddyfile(h.Dispenser)
	})
}

type Takeover struct {
	Paths         []string `json:"paths"`
	SkipQuery     []string `json:"skip_query"`
	RDParam       string   `json:"rd_param"`
	Entry         string   `json:"entry"`
	NativeMinutes int      `json:"native_minutes"`
}

type SSO struct {
	Public             bool           `json:"public,omitempty"`
	Takeover           *Takeover      `json:"takeover,omitempty"`
	AppLogin           bool           `json:"app_login,omitempty"`
	PublicKey          string         `json:"public_key"`
	Core               string         `json:"core"`
	Login              string         `json:"login"`
	Skip               []string       `json:"skip,omitempty"`
	Trust              []string       `json:"trust,omitempty"`
	UserHeader         string         `json:"user_header,omitempty"`
	RevocationKey      string         `json:"revocation_key,omitempty"`
	RevocationInterval caddy.Duration `json:"revocation_interval,omitempty"`
	revocationSource   revocationSource
	revocations        *revocationPoll
	trusted            []netip.Prefix
	key                ed25519.PublicKey
	client             *http.Client
	mu                 sync.Mutex
	cache              map[[32]byte]*refreshResult
}

type refreshResult struct {
	done   chan struct{}
	until  time.Time
	status int
	header http.Header
	body   []byte
}

func (SSO) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.wharf_sso", New: func() caddy.Module { return new(SSO) }}
}
func (s *SSO) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "public_key":
				if !d.Args(&s.PublicKey) {
					return d.ArgErr()
				}
			case "core":
				if !d.Args(&s.Core) {
					return d.ArgErr()
				}
			case "login":
				if !d.Args(&s.Login) {
					return d.ArgErr()
				}
			case "revocation_key":
				if !d.AllArgs(&s.RevocationKey) {
					return d.ArgErr()
				}
			case "revocation_interval":
				var value string
				if !d.AllArgs(&value) {
					return d.ArgErr()
				}
				interval, err := caddy.ParseDuration(value)
				if err != nil || interval < time.Second {
					return d.Err("门禁吊销拉取间隔至少为 1 秒")
				}
				s.RevocationInterval = caddy.Duration(interval)
			case "public":
				s.Public = true
			case "takeover":
				var value string
				if !d.Args(&value) {
					return d.ArgErr()
				}
				config, err := base64.RawURLEncoding.DecodeString(value)
				if err != nil || json.Unmarshal(config, &s.Takeover) != nil || s.Takeover == nil {
					return d.Err("接管登录页配置无效")
				}
			case "app_login":
				var value string
				if !d.Args(&value) || value != "on" {
					return d.ArgErr()
				}
				s.AppLogin = true
			case "user_header":
				if !d.Args(&s.UserHeader) {
					return d.ArgErr()
				}
			case "trust":
				s.Trust = d.RemainingArgs()
			case "skip":
				s.Skip = d.RemainingArgs()
			default:
				return d.Errf("未知门禁选项 %s", d.Val())
			}
		}
	}
	return nil
}
func (s *SSO) Provision(ctx caddy.Context) error {
	key, err := base64.StdEncoding.DecodeString(s.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("门禁公钥无效")
	}
	for _, raw := range []string{s.Core, s.Login} {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("门禁地址无效")
		}
	}
	for _, raw := range s.Trust {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return fmt.Errorf("门禁免登录网段无效")
		}
		s.trusted = append(s.trusted, prefix)
	}
	s.key = key
	s.client = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	s.cache = make(map[[32]byte]*refreshResult)
	return s.provisionRevocations()
}

// 所有 Cookie 头合并处理，保留应用自己的 cookie。
func stripCookies(r *http.Request) (string, string) {
	var access, refresh string
	var keep []string
	for _, line := range r.Header.Values("Cookie") {
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			name, value, ok := strings.Cut(part, "=")
			if ok && (name == "wharf_gate" || name == "wharf_gate_rt" || name == "wharf_sso" || name == "wharf_native" || name == takeoverCookie) {
				if value != "" {
					if name == "wharf_gate" && access == "" {
						access = value
					}
					if name == "wharf_gate_rt" && refresh == "" {
						refresh = value
					}
				}
			} else if part != "" {
				keep = append(keep, part)
			}
		}
	}
	r.Header.Del("Cookie")
	if len(keep) > 0 {
		r.Header.Set("Cookie", strings.Join(keep, "; "))
	}
	return access, refresh
}
func verify(key ed25519.PublicKey, token, host string, now int64) (string, int64, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", 0, false
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", 0, false
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(header, &h) != nil || h.Alg != "EdDSA" {
		return "", 0, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return "", 0, false
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", 0, false
	}
	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Aud string `json:"aud"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	if json.Unmarshal(data, &claims) != nil || claims.Iss != "wharf" || claims.Sub == "" || claims.Aud == "" || claims.Aud != host || claims.Iat <= 0 || claims.Exp <= now-CLOCK_SKEW {
		return "", 0, false
	}
	return claims.Sub, claims.Iat, true
}
func originalURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
}
func (s *SSO) setUser(r *http.Request, user string) {
	if s.UserHeader != "" && user != "" {
		r.Header.Set(s.UserHeader, user)
	}
	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		repl.Set("http.wharf_sso.user", user)
	}
}
func refreshCacheKey(r *http.Request, token string) [32]byte {
	// 按目标域名隔离结果，避免不同站点共享跳转响应；缓存不保存原始凭据。
	return sha256.Sum256([]byte(token + "\x00" + r.Host))
}

func (s *SSO) refresh(r *http.Request, token string) *refreshResult {
	key := refreshCacheKey(r, token)
	s.mu.Lock()
	if old := s.cache[key]; old != nil && (old.until.IsZero() || time.Now().Before(old.until)) {
		s.mu.Unlock()
		return waitRefresh(r.Context(), old)
	}
	for k, v := range s.cache {
		if !v.until.IsZero() && time.Now().After(v.until) {
			delete(s.cache, k)
		}
	}
	result := &refreshResult{done: make(chan struct{})}
	cached := len(s.cache) < 1000
	if cached {
		s.cache[key] = result
	}
	s.mu.Unlock()
	go s.fetchRefresh(r.Clone(context.Background()), token, key, cached, result)
	return waitRefresh(r.Context(), result)
}

func waitRefresh(ctx context.Context, result *refreshResult) *refreshResult {
	select {
	case <-result.done:
		return result
	case <-ctx.Done():
		return &refreshResult{status: 502, body: []byte("登录服务暂时连不上")}
	}
}

func (s *SSO) fetchRefresh(r *http.Request, token string, key [32]byte, cached bool, result *refreshResult) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(s.Core, "/")+"/gate/refresh", nil)
	if err == nil {
		req.AddCookie(&http.Cookie{Name: "wharf_gate_rt", Value: token})
		req.Header.Set("X-Forwarded-Host", r.Host)
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		req.Header.Set("X-Forwarded-Proto", scheme)
		req.Header.Set("X-Forwarded-Uri", r.URL.RequestURI())
		req.Header.Set("X-Forwarded-Method", r.Method)
		req.Header.Set("Accept", r.Header.Get("Accept"))
		var resp *http.Response
		resp, err = s.client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			result.status, result.header = resp.StatusCode, resp.Header.Clone()
			result.body, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		}
	}
	if err != nil {
		result.status = 502
		result.header = nil
		result.body = []byte("登录服务暂时连不上")
	}
	s.mu.Lock()
	result.until = time.Now().Add(30 * time.Second)
	// 只复用成功结果；失败跳转含当前请求的地址和方法。
	if cached && result.status != 200 {
		delete(s.cache, key)
	}
	close(result.done)
	s.mu.Unlock()
}
func (s *SSO) checkKey(w http.ResponseWriter, r *http.Request, key string) (bool, error) {
	req, err := http.NewRequestWithContext(r.Context(), "GET", strings.TrimRight(s.Core, "/")+"/gate/key", nil)
	if err == nil {
		req.Header.Set("X-Wharf-Key", key)
		req.Header.Set("X-Forwarded-Host", r.Host)
		if peer, e := netip.ParseAddrPort(r.RemoteAddr); e == nil {
			req.Header.Set("X-Forwarded-For", peer.Addr().Unmap().String())
		}
		var resp *http.Response
		resp, err = s.client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				return true, nil
			}
			body, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			if e == nil {
				if ct := resp.Header.Get("Content-Type"); ct != "" {
					w.Header().Set("Content-Type", ct)
				}
				if location := resp.Header.Get("Location"); location != "" {
					w.Header().Set("Location", location)
				}
				w.WriteHeader(resp.StatusCode)
				_, e = w.Write(body)
				return false, e
			}
		}
	}
	http.Error(w, "登录服务暂时连不上", http.StatusBadGateway)
	return false, nil
}
func requestHost(r *http.Request) string {
	host := strings.TrimSpace(r.Host)
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	return strings.ToLower(host)
}

func hasDotSegment(request string) bool {
	for _, segment := range strings.Split(request, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func isWharfPath(request string) bool {
	return request == "/_wharf" || strings.HasPrefix(request, "/_wharf/")
}

var rawPathSeparators = strings.NewReplacer("%2e", ".", "%2f", "/")

func normalizeRequestPath(r *http.Request) (clean string, rawHasEncodedSlash bool, ok bool) {
	request := r.URL.Path
	if !strings.HasPrefix(request, "/") || strings.ContainsFunc(request, func(c rune) bool {
		return c == '\\' || c < 0x20 || c == 0x7f
	}) || hasDotSegment(request) {
		return "", false, false
	}
	raw := strings.ToLower(r.URL.RawPath)
	if strings.Contains(raw, "%5c") ||
		(raw != "" && hasDotSegment(rawPathSeparators.Replace(raw))) {
		return "", false, false
	}
	clean = path.Clean(request)
	if isWharfPath(clean) && (request != clean || raw != "") {
		return "", false, false
	}
	return clean, strings.Contains(raw, "%2f"), true
}

func matchesPath(request string, prefixes []string, encodedPath string) bool {
	for _, prefix := range prefixes {
		p := path.Clean(prefix)
		if p == "/" || (encodedPath != "" && !strings.HasPrefix(encodedPath, p+"/")) {
			continue
		}
		if request == p || strings.HasPrefix(request, p+"/") {
			return true
		}
	}
	return false
}

func localPath(raw string) (*url.URL, bool) {
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\\\r\n\t") {
		return nil, false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, false
	}
	clean, _, ok := normalizeRequestPath(&http.Request{URL: u})
	if !ok || strings.HasPrefix(u.Path, "//") || isWharfPath(clean) {
		return nil, false
	}
	return u, true
}

func (t *Takeover) loginPath(r *http.Request) string {
	query := r.URL.Query()
	for _, skip := range t.SkipQuery {
		if query.Has(skip) {
			return ""
		}
	}
	rd := t.Entry
	if rd == "" {
		rd = "/"
	}
	if t.RDParam != "" {
		if candidate := query.Get(t.RDParam); candidate != "" {
			if parsed, ok := localPath(candidate); ok && !matchesPath(path.Clean(parsed.Path), t.Paths, "") {
				rd = candidate
			}
		}
	}
	return "/_wharf/login?" + url.Values{"rd": {rd}}.Encode()
}

func (s *SSO) native(w http.ResponseWriter, r *http.Request) {
	rd := r.URL.Query().Get("rd")
	parsed, ok := localPath(rd)
	if r.Method != http.MethodGet || !ok || !matchesPath(path.Clean(parsed.Path), s.Takeover.Paths, "") {
		http.Error(w, "跳转地址不对", http.StatusBadRequest)
		return
	}
	minutes := s.Takeover.NativeMinutes
	if minutes == 0 {
		minutes = 10
	}
	w.Header().Set("Cache-Control", "no-store")
	http.SetCookie(w, &http.Cookie{
		Name: "wharf_native", Value: "1", MaxAge: minutes * 60, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, rd, http.StatusFound)
}

func (s *SSO) silentLogin(w http.ResponseWriter, r *http.Request, loginPath string) {
	query := url.Values{
		"rd":     {"https://" + r.Host + loginPath},
		"silent": {"1"},
		"native": {r.URL.RequestURI()},
	}
	redirectAppLogin(w, r, strings.TrimRight(s.Login, "/")+"/gate/login?"+query.Encode(), true)
}

func redirectAppLogin(w http.ResponseWriter, r *http.Request, target string, takeover bool) {
	if takeover {
		http.SetCookie(w, &http.Cookie{
			Name: takeoverCookie, Value: "1", MaxAge: 60, Path: "/",
			HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		})
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *SSO) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	clean, encodedSlash, ok := normalizeRequestPath(r)
	if !ok {
		http.Error(w, "请求路径无效", http.StatusBadRequest)
		return nil
	}
	if s.UserHeader != "" {
		r.Header.Del(s.UserHeader)
	}
	keyValues, hasKey := r.Header["X-Wharf-Key"]
	r.Header.Del("X-Wharf-Key")
	if strings.HasPrefix(clean, "/_wharf/") && (!s.Public || s.AppLogin || s.Takeover != nil) {
		if s.Public && s.Takeover != nil && clean == "/_wharf/native" {
			s.native(w, r)
			return nil
		}
		return next.ServeHTTP(w, r)
	}
	marker, markerError := r.Cookie("wharf_sso")
	native, _ := r.Cookie("wharf_native")
	recentTakeover, _ := r.Cookie(takeoverCookie)
	html := r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html")
	takeoverPath := ""
	if s.Takeover != nil && html && matchesPath(clean, s.Takeover.Paths, "") &&
		(recentTakeover == nil || recentTakeover.Value != "1") &&
		(marker == nil || marker.Value != "fail") && (!s.Public || native == nil || native.Value != "1") {
		takeoverPath = s.Takeover.loginPath(r)
	}
	appLogin := takeoverPath
	if s.Takeover == nil && s.AppLogin && markerError != nil && html {
		appLogin = "/_wharf/login?rd=" + url.QueryEscape(r.URL.RequestURI())
	}
	access, refresh := stripCookies(r)
	if s.Public && takeoverPath == "" {
		return next.ServeHTTP(w, r)
	}
	s.setUser(r, "")
	var encodedPath string
	if encodedSlash {
		encodedPath = r.URL.RawPath
	}
	if matchesPath(clean, s.Skip, encodedPath) {
		return next.ServeHTTP(w, r)
	}
	if peer, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		for _, prefix := range s.trusted {
			if prefix.Contains(peer.Addr().Unmap()) {
				return next.ServeHTTP(w, r)
			}
		}
	}
	if hasKey {
		ok, err := s.checkKey(w, r, strings.Join(keyValues, ","))
		if ok {
			return next.ServeHTTP(w, r)
		}
		return err
	}
	if user, ok := s.verifyAccess(access, requestHost(r), time.Now().Unix()); ok {
		s.setUser(r, user)
		if appLogin != "" {
			redirectAppLogin(w, r, appLogin, takeoverPath != "")
			return nil
		}
		return next.ServeHTTP(w, r)
	}
	if refresh != "" {
		result := s.refresh(r, refresh)
		if result.status == http.StatusOK && !s.refreshAllowed(result, requestHost(r), time.Now().Unix()) {
			key := refreshCacheKey(r, refresh)
			s.mu.Lock()
			if s.cache[key] == result {
				delete(s.cache, key)
			}
			s.mu.Unlock()
			result = &refreshResult{status: http.StatusUnauthorized, body: []byte("需要登录")}
		}
		for _, cookie := range result.header.Values("Set-Cookie") {
			w.Header().Add("Set-Cookie", cookie)
		}
		if result.status == 200 {
			s.setUser(r, result.header.Get("X-Wharf-User"))
			if appLogin != "" {
				redirectAppLogin(w, r, appLogin, takeoverPath != "")
				return nil
			}
			return next.ServeHTTP(w, r)
		}
		if s.Public {
			s.silentLogin(w, r, takeoverPath)
			return nil
		}
		if location := result.header.Get("Location"); location != "" {
			w.Header().Set("Location", location)
		}
		w.WriteHeader(result.status)
		_, err := w.Write(result.body)
		return err
	}
	if s.Public {
		s.silentLogin(w, r, takeoverPath)
	} else if html {
		http.Redirect(w, r, strings.TrimRight(s.Login, "/")+"/gate/login?rd="+url.QueryEscape(originalURL(r)), http.StatusFound)
	} else {
		http.Error(w, "需要登录", http.StatusUnauthorized)
	}
	return nil
}
