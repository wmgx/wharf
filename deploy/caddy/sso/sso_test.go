package sso

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func token(key ed25519.PrivateKey, alg, iss string, exp int64) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"alg":%q,"typ":"JWT"}`, alg)))
	p := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d,"iat":1700000000,"iss":%q,"sub":"admin"}`, exp, iss)))
	raw := h + "." + p
	return raw + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(raw)))
}
func plugin(t *testing.T, core string) *SSO {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	s := &SSO{PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), Core: core, Login: "https://core.example.test"}
	if err := s.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	return s
}
func TestStripCookies(t *testing.T) {
	for _, input := range [][]string{
		{"wharf_gate=a;other=1; wharf_gate_rt=b;my_wharf_gate=1"},
		{"other=1;wharf_gate_rt=b;wharf_gate=a; my_wharf_gate=1"},
		{"wharf_gate=a", "other=1;wharf_gate_rt=b;my_wharf_gate=1"},
		{"wharf_gate=;wharf_gate=a;wharf_gate=c;wharf_gate_rt=b;other=1;my_wharf_gate=1"},
	} {
		r := httptest.NewRequest("GET", "https://a.example.test/", nil)
		r.Header["Cookie"] = input
		a, b := stripCookies(r)
		if a != "a" || b != "b" || r.Header.Get("Cookie") != "other=1; my_wharf_gate=1" || len(r.Header.Values("Cookie")) != 1 {
			t.Fatalf("cookie 处理错误: %v", input)
		}
	}
	for _, input := range []string{"wharf_gate=a", "wharf_gate_rt=b", "wharf_gate=a;wharf_gate_rt=b"} {
		r := httptest.NewRequest("GET", "https://a.example.test/", nil)
		r.Header.Set("Cookie", input)
		stripCookies(r)
		if r.Header.Get("Cookie") != "" {
			t.Fatal("残留门禁 cookie")
		}
	}
}
func TestVerify(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	pub := key.Public().(ed25519.PublicKey)
	good := token(key, "EdDSA", "wharf", 1700000600)
	for _, bad := range []string{good[:len(good)-2] + "xx", token(key, "EdDSA", "wharf", 1699999900), token(key, "none", "wharf", 1700000600), token(key, "HS256", "wharf", 1700000600), token(key, "EdDSA", "other", 1700000600), "hash.1700000600.signature"} {
		if _, ok := verify(pub, bad, 1700000000); ok {
			t.Fatal("无效凭据被接受")
		}
	}
	if user, ok := verify(pub, good, 1700000000); !ok || user != "admin" {
		t.Fatal("有效凭据被拒")
	}
	if _, ok := verify(pub, token(key, "EdDSA", "wharf", 1699999980), 1700000000); !ok {
		t.Fatal("20 秒时钟差被拒")
	}
	// Rust 与 Go 共用固定种子、内容及凭据。
	const fixture = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MDAwMDA2MDAsImlhdCI6MTcwMDAwMDAwMCwiaXNzIjoid2hhcmYiLCJzdWIiOiJhZG1pbiJ9.J-x_gW3JdQqN7lpvfll72TH40DsjtJCgW3TDzgM20dlmY78RWQESgnYWBtD2X4Pki4WpS-F6s0poysRCdKrGAg"
	if good != fixture {
		t.Fatal("跨语言凭据不一致")
	}
}
func TestRefreshPostAndConcurrent(t *testing.T) {
	var calls atomic.Int32
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		if r.Method != "GET" || r.Header.Get("X-Forwarded-Host") != "a.example.test" {
			t.Error("续签请求不对")
		}
		w.Header().Add("Set-Cookie", "wharf_gate=new; Path=/; Secure; HttpOnly")
		w.Header().Set("X-Wharf-User", "admin")
	}))
	defer core.Close()
	s := plugin(t, core.URL)
	app := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		body, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || string(body) != "完整请求体" || r.Header.Get("Cookie") != "other=1" {
			t.Error("原请求被改变")
		}
		w.Header().Add("Set-Cookie", "app=1; Path=/")
		w.WriteHeader(200)
		return nil
	})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("POST", "https://a.example.test/x", strings.NewReader("完整请求体"))
			r.Header.Set("Cookie", "wharf_gate=expired;wharf_gate_rt=long;other=1")
			w := httptest.NewRecorder()
			if err := s.ServeHTTP(w, r, app); err != nil {
				t.Error(err)
			}
			if w.Code != 200 || len(w.Header().Values("Set-Cookie")) != 2 {
				t.Error("续签响应丢失")
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("控制面被问了 %d 次", calls.Load())
	}
}
func TestFailuresAndSkip(t *testing.T) {
	app := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if r.Header.Get("Cookie") != "other=1" {
			t.Error("排除路径残留凭据")
		}
		w.WriteHeader(200)
		return nil
	})
	s := plugin(t, "http://127.0.0.1:1")
	s.Skip = []string{"/api"}
	for _, path := range []string{"/api", "/api/x"} {
		r := httptest.NewRequest("GET", "https://a.example.test"+path, nil)
		r.Header.Set("Cookie", "wharf_gate=a;wharf_gate_rt=b;other=1")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r, app)
		if w.Code != 200 {
			t.Fatal("排除路径被挡")
		}
	}
	for _, method := range []string{"GET", "POST"} {
		r := httptest.NewRequest(method, "https://a.example.test/x?a=1&b=2", nil)
		r.Header.Set("Accept", "text/html")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r, app)
		if method == "GET" {
			u, _ := url.Parse(w.Header().Get("Location"))
			if w.Code != 302 || u.Query().Get("rd") != "https://a.example.test/x?a=1&b=2" {
				t.Fatal("跳转地址不对")
			}
		} else if w.Code != 401 {
			t.Fatal("POST 应拒绝")
		}
	}
	for _, status := range []int{302, 401} {
		core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "/login")
			w.Header().Add("Set-Cookie", "wharf_gate_rt=; Max-Age=0")
			w.WriteHeader(status)
			fmt.Fprint(w, "原正文")
		}))
		p := plugin(t, core.URL)
		r := httptest.NewRequest("POST", "https://a.example.test/x", nil)
		r.Header.Set("Cookie", "wharf_gate_rt=long")
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r, app)
		core.Close()
		if w.Code != status || w.Body.String() != "原正文" || w.Header().Get("Location") != "/login" || len(w.Header().Values("Set-Cookie")) != 1 {
			t.Fatal("错误应答被改变")
		}
	}
}

func TestTrustDirectPeer(t *testing.T) {
	s := plugin(t, "http://127.0.0.1:1")
	s.trusted = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}
	for _, peer := range []string{"100.64.0.7:1234", "172.30.0.7:1234"} {
		r := httptest.NewRequest("GET", "https://a.example.test/", nil)
		r.RemoteAddr = peer
		r.Header.Set("Accept", "text/html")
		r.Header.Set("X-Forwarded-For", "100.64.0.7")
		r.Header.Set("Cookie", "wharf_gate=bad;wharf_gate_rt=bad;other=1")
		// 非信任来源不用长凭据，以验证伪造转发头仍然走登录。
		if strings.HasPrefix(peer, "172.") {
			r.Header.Set("Cookie", "other=1")
		}
		w := httptest.NewRecorder()
		err := s.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			if r.Header.Get("Cookie") != "other=1" {
				t.Fatal("残留门禁cookie")
			}
			w.WriteHeader(200)
			return nil
		}))
		want := 302
		if strings.HasPrefix(peer, "100.") {
			want = 200
		}
		if err != nil || w.Code != want {
			t.Fatalf("来源判定失败: %s %d", peer, w.Code)
		}
	}
}
func TestAccessKey(t *testing.T) {
	var calls int
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/gate/key" || r.Header.Get("X-Wharf-Key") != "lab-key" || r.Header.Get("X-Forwarded-Host") != "a.example.test" || r.Header.Get("X-Forwarded-For") != "203.0.113.7" {
			t.Error("校验请求不对")
		}
	}))
	defer core.Close()
	s := plugin(t, core.URL)
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("POST", "https://a.example.test/", strings.NewReader("body"))
		r.RemoteAddr = "203.0.113.7:1234"
		r.Header.Set("X-Wharf-Key", "lab-key")
		r.Header.Set("Cookie", "wharf_gate=bad;wharf_gate_rt=bad;other=1")
		w := httptest.NewRecorder()
		err := s.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			b, _ := io.ReadAll(r.Body)
			if r.Header.Get("X-Wharf-Key") != "" || r.Header.Get("Cookie") != "other=1" || string(b) != "body" {
				t.Error("凭证残留或正文丢失")
			}
			w.WriteHeader(200)
			return nil
		}))
		if err != nil || w.Code != 200 {
			t.Fatal("有效凭证被拒")
		}
	}
	if calls != 2 {
		t.Fatal("访问凭证被缓存")
	}
}
func TestInvalidKeyDoesNotFallback(t *testing.T) {
	calls := 0
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(401)
		fmt.Fprint(w, `{"error":"访问凭证无效"}`)
	}))
	defer core.Close()
	s := plugin(t, core.URL)
	r := httptest.NewRequest("GET", "https://a.example.test/", nil)
	r.Header.Set("X-Wharf-Key", "wrong")
	r.Header.Set("Cookie", "wharf_gate="+token(ed25519.NewKeyFromSeed(make([]byte, 32)), "EdDSA", "wharf", time.Now().Unix()+600))
	w := httptest.NewRecorder()
	if err := s.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { t.Fatal("无效凭证回退cookie"); return nil })); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || w.Code != 401 || w.Body.String() != `{"error":"访问凭证无效"}` {
		t.Fatal("未原样拒绝凭证")
	}
}

func TestUserHeaderAccess(t *testing.T) {
	s := plugin(t, "http://127.0.0.1:1")
	s.UserHeader = "Remote-User"
	r := httptest.NewRequest("GET", "https://a.example.test/", nil)
	r.Header["Remote-User"] = []string{"someone-else", "another"}
	r.AddCookie(&http.Cookie{Name: "wharf_gate", Value: token(ed25519.NewKeyFromSeed(make([]byte, 32)), "EdDSA", "wharf", time.Now().Unix()+60)})
	called := false
	s.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		if values := r.Header.Values("Remote-User"); len(values) != 1 || values[0] != "admin" {
			t.Fatal("用户名未替换伪造头")
		}
		return nil
	}))
	if !called {
		t.Fatal("有效凭据未放行")
	}
}
func TestUserHeaderRefresh(t *testing.T) {
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("X-Wharf-User", "admin") }))
	defer core.Close()
	s := plugin(t, core.URL)
	s.UserHeader = "Remote-Name"
	r := httptest.NewRequest("GET", "https://a.example.test/", nil)
	r.Header.Add("Remote-Name", "someone-else")
	r.AddCookie(&http.Cookie{Name: "wharf_gate_rt", Value: "long"})
	called := false
	s.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		if values := r.Header.Values("Remote-Name"); len(values) != 1 || values[0] != "admin" {
			t.Fatal("续签未传用户名")
		}
		return nil
	}))
	if !called {
		t.Fatal("续签未放行")
	}
}
func TestUserHeaderBypass(t *testing.T) {
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer core.Close()
	for _, bypass := range []string{"skip", "key", "trust"} {
		s := plugin(t, core.URL)
		s.UserHeader = "Remote-User"
		r := httptest.NewRequest("GET", "https://a.example.test/api", nil)
		r.Header["Remote-User"] = []string{"someone-else", "another"}
		switch bypass {
		case "skip":
			s.Skip = []string{"/api"}
		case "key":
			r.Header.Set("X-Wharf-Key", "lab-key")
		case "trust":
			s.trusted = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}
			r.RemoteAddr = "100.64.0.7:1234"
		}
		called := false
		s.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			called = true
			if len(r.Header.Values("Remote-User")) != 0 {
				t.Fatal("绕过门禁残留伪造用户名：", bypass)
			}
			return nil
		}))
		if !called {
			t.Fatal("未放行：", bypass)
		}
	}
}

func TestAppLoginRedirect(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "wharf_gate=new; Secure")
		w.Header().Set("X-Wharf-User", "admin")
	}))
	defer core.Close()
	for _, credential := range []string{"wharf_gate=" + token(key, "EdDSA", "wharf", time.Now().Unix()+600), "wharf_gate_rt=refresh"} {
		s := plugin(t, core.URL)
		s.AppLogin = true
		r := httptest.NewRequest("GET", "https://a.example.test/a?x=1&y=2", nil)
		r.Header.Set("Accept", "text/html")
		r.Header.Set("Cookie", credential)
		w := httptest.NewRecorder()
		err := s.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { t.Fatal("不能转给应用"); return nil }))
		if err != nil || w.Code != 302 || w.Header().Get("Location") != "/_wharf/login?rd=%2Fa%3Fx%3D1%26y%3D2" {
			t.Fatal("代登录跳转不对")
		}
		if strings.HasPrefix(credential, "wharf_gate_rt=") && w.Header().Get("Set-Cookie") == "" {
			t.Fatal("续签 cookie 丢失")
		}
	}
}
func TestAppLoginBypass(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer core.Close()
	for _, mode := range []string{"marker", "json", "post", "key", "skip", "trust"} {
		t.Run(mode, func(t *testing.T) {
			s := plugin(t, core.URL)
			s.AppLogin = true
			r := httptest.NewRequest("GET", "https://a.example.test/", nil)
			r.Header.Set("Accept", "text/html")
			r.Header.Set("Cookie", "wharf_gate="+token(key, "EdDSA", "wharf", time.Now().Unix()+600)+"; wharf_gate_rt=refresh; app=1")
			switch mode {
			case "marker":
				r.Header.Add("Cookie", "wharf_sso=fail")
			case "json":
				r.Header.Set("Accept", "application/json")
			case "post":
				r.Method = "POST"
			case "key":
				r.Header.Set("X-Wharf-Key", "lab-key")
			case "skip":
				s.Skip = []string{"/"}
			case "trust":
				s.trusted = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
				r.RemoteAddr = "203.0.113.1:1234"
			}
			called := false
			err := s.ServeHTTP(httptest.NewRecorder(), r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				called = true
				if r.Header.Get("Cookie") != "app=1" {
					t.Fatal("应用收到门禁 cookie")
				}
				return nil
			}))
			if err != nil || !called {
				t.Fatal("请求不应跳转")
			}
		})
	}
}

func TestTakeover(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	const login = "https://app.example.test/login/continue?rd=%2F%2Foutside.example.test"
	const core = "https://core.example.test"
	for _, test := range []struct {
		name, target, cookie string
	}{
		{"有凭证", login, "wharf_gate=" + token(key, "EdDSA", "wharf", time.Now().Unix()+60)},
		{"无凭证", login, ""},
		{"原生登录", login, "wharf_native=1"},
		{"退出登录", login + "&logout", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := plugin(t, "http://127.0.0.1:1")
			s.Login, s.Public = core, true
			s.Takeover = &Takeover{Paths: []string{"/login"}, SkipQuery: []string{"logout"}, RDParam: "rd", Entry: "/console"}
			request := func(target, cookie string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodGet, target, nil)
				r.Header.Set("Accept", "text/html")
				r.Header.Set("Cookie", cookie)
				w := httptest.NewRecorder()
				err := s.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					if r.Header.Get("Cookie") != "" {
						t.Fatal("应用收到 Wharf cookie")
					}
					w.WriteHeader(http.StatusNoContent)
					return nil
				}))
				if err != nil {
					t.Fatal(err)
				}
				return w
			}
			first := request(test.target, test.cookie)
			switch test.name {
			case "有凭证":
				if first.Code != 302 || first.Header().Get("Location") != "/_wharf/login?rd=%2Fconsole" {
					t.Fatal("应代登录并回到 entry")
				}
			case "无凭证":
				loc, err := url.Parse(first.Header().Get("Location"))
				if err != nil || first.Code != 302 || loc.Host != "core.example.test" || loc.Path != "/gate/login" ||
					loc.Query().Get("silent") != "1" || loc.Query().Get("rd") != "https://app.example.test/_wharf/login?rd=%2Fconsole" {
					t.Fatal("应静默检查 Wharf 会话")
				}
				// 模拟控制面确认访客后跳回当前域名。
				native := loc.Query().Get("native")
				back := request("https://app.example.test/_wharf/native?rd="+url.QueryEscape(native), "")
				cookies := back.Result().Cookies()
				if back.Code != 302 || back.Header().Get("Location") != native || len(cookies) != 1 {
					t.Fatal("应跳回原生登录页")
				}
				c := cookies[0]
				if c.Name != "wharf_native" || c.MaxAge != 600 || c.Path != "/" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
					t.Fatal("原生登录 cookie 无效")
				}
				if request("https://app.example.test"+native, c.Name+"="+c.Value).Code != 204 {
					t.Fatal("回到原生登录页后应直接放行")
				}
			default:
				if first.Code != 204 {
					t.Fatal("应直接放行")
				}
			}
		})
	}
}
