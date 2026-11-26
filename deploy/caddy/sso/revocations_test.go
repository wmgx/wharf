package sso

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestRevocationRejectsOldCookieAndKeepsNewCookie(t *testing.T) {
	now := time.Now().Unix()
	var unavailable atomic.Bool
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/gate/revocations" || r.Header.Get("X-Wharf-Key") != "fixture" {
			t.Error("吊销回调请求不对")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if unavailable.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]int64{"admin": now - 1})
	}))
	defer core.Close()

	s := plugin(t, core.URL)
	s.revocations = &revocationPoll{}
	source := revocationSource{core: core.URL, key: "fixture"}
	serve := func(issued int64) int {
		t.Helper()
		host := "a.example.test"
		key := ed25519.NewKeyFromSeed(make([]byte, 32))
		r := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
		r.AddCookie(&http.Cookie{Name: "wharf_gate", Value: tokenAt(key, "EdDSA", "wharf", host, issued, issued+gateAccessTTL)})
		w := httptest.NewRecorder()
		err := s.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
			w.WriteHeader(http.StatusNoContent)
			return nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		return w.Code
	}
	if got := serve(now - 2); got != http.StatusNoContent {
		t.Fatalf("吊销前状态码 %d", got)
	}
	s.revocations.pull(context.Background(), s.client, source)
	if got := serve(now - 2); got != http.StatusUnauthorized {
		t.Fatalf("吊销后旧凭据状态码 %d", got)
	}
	unavailable.Store(true)
	s.revocations.pull(context.Background(), s.client, source)
	if got := serve(now - 1); got != http.StatusUnauthorized {
		t.Fatalf("回调失败后同秒凭据状态码 %d", got)
	}
	if got := serve(now); got != http.StatusNoContent {
		t.Fatalf("吊销后新凭据状态码 %d", got)
	}
}
