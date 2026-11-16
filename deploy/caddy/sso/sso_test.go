package sso

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
