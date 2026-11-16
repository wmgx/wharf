package sso

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const CLOCK_SKEW = 30

func init() {
	caddy.RegisterModule(SSO{})
	httpcaddyfile.RegisterHandlerDirective("wharf_sso", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		var s SSO
		return &s, s.UnmarshalCaddyfile(h.Dispenser)
	})
}

type SSO struct {
	PublicKey  string   `json:"public_key"`
	Core       string   `json:"core"`
	Login      string   `json:"login"`
	Skip       []string `json:"skip,omitempty"`
	Trust      []string `json:"trust,omitempty"`
	UserHeader string   `json:"user_header,omitempty"`
	trusted    []netip.Prefix
	key        ed25519.PublicKey
	client     *http.Client
	mu         sync.Mutex
	cache      map[[32]byte]*refreshResult
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
	return nil
}

// 所有 Cookie 头合并处理，保留应用自己的 cookie。
func stripCookies(r *http.Request) (string, string) {
	var access, refresh string
	var keep []string
	for _, line := range r.Header.Values("Cookie") {
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			name, value, ok := strings.Cut(part, "=")
			if ok && (name == "wharf_gate" || name == "wharf_gate_rt") {
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
func verify(key ed25519.PublicKey, token string, now int64) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(header, &h) != nil || h.Alg != "EdDSA" {
		return "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return "", false
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Exp int64  `json:"exp"`
	}
	if json.Unmarshal(data, &claims) != nil || claims.Iss != "wharf" || claims.Sub == "" || claims.Exp <= now-CLOCK_SKEW {
		return "", false
	}
	return claims.Sub, true
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
func (s *SSO) refresh(r *http.Request, token string) *refreshResult {
	// 按目标域名隔离结果，避免不同站点共享跳转响应；缓存不保存原始凭据。
	key := sha256.Sum256([]byte(token + "\x00" + r.Host))
	s.mu.Lock()
	if old := s.cache[key]; old != nil && (old.until.IsZero() || time.Now().Before(old.until)) {
		s.mu.Unlock()
		select {
		case <-old.done:
			return old
		case <-r.Context().Done():
			return &refreshResult{status: 502, body: []byte("登录服务暂时连不上")}
		}
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
	req, err := http.NewRequestWithContext(r.Context(), "GET", strings.TrimRight(s.Core, "/")+"/gate/refresh", nil)
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
	return result
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
func (s *SSO) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if strings.HasPrefix(r.URL.Path, "/_wharf/") {
		return next.ServeHTTP(w, r)
	}
	if s.UserHeader != "" {
		r.Header.Del(s.UserHeader)
	}
	access, refresh := stripCookies(r)
	keyValues, hasKey := r.Header["X-Wharf-Key"]
	key := strings.Join(keyValues, ",")
	r.Header.Del("X-Wharf-Key")
	s.setUser(r, "")
	for _, p := range s.Skip {
		if r.URL.Path == p || strings.HasPrefix(r.URL.Path, strings.TrimRight(p, "/")+"/") {
			return next.ServeHTTP(w, r)
		}
	}
	if peer, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		for _, prefix := range s.trusted {
			if prefix.Contains(peer.Addr().Unmap()) {
				return next.ServeHTTP(w, r)
			}
		}
	}
	if hasKey {
		ok, err := s.checkKey(w, r, key)
		if ok {
			return next.ServeHTTP(w, r)
		}
		return err
	}
	if user, ok := verify(s.key, access, time.Now().Unix()); ok {
		s.setUser(r, user)
		return next.ServeHTTP(w, r)
	}
	if refresh != "" {
		result := s.refresh(r, refresh)
		for _, cookie := range result.header.Values("Set-Cookie") {
			w.Header().Add("Set-Cookie", cookie)
		}
		if result.status == 200 {
			s.setUser(r, result.header.Get("X-Wharf-User"))
			return next.ServeHTTP(w, r)
		}
		if location := result.header.Get("Location"); location != "" {
			w.Header().Set("Location", location)
		}
		w.WriteHeader(result.status)
		_, err := w.Write(result.body)
		return err
	}
	if r.Method == "GET" && strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Redirect(w, r, strings.TrimRight(s.Login, "/")+"/gate/login?rd="+url.QueryEscape(originalURL(r)), http.StatusFound)
	} else {
		http.Error(w, "需要登录", http.StatusUnauthorized)
	}
	return nil
}
