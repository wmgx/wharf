package sso

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
)

const gateAccessTTL = 600 // 与控制面的 ACCESS_TTL 一致。

var revocationPolls = caddy.NewUsagePool()

type revocationSource struct {
	core     string
	key      string
	interval time.Duration
}

type revocationPoll struct {
	cancel  context.CancelFunc
	mu      sync.RWMutex
	cutoffs map[string]int64
}

func (s *SSO) provisionRevocations() error {
	if s.RevocationKey == "" {
		return nil
	}
	key, err := hex.DecodeString(s.RevocationKey)
	if err != nil || len(key) != 32 {
		return fmt.Errorf("门禁吊销回调密钥格式不对")
	}
	interval := time.Duration(s.RevocationInterval)
	if interval == 0 {
		interval = 15 * time.Second
	}
	if interval < time.Second {
		return fmt.Errorf("门禁吊销拉取间隔至少为 1 秒")
	}
	s.revocationSource = revocationSource{strings.TrimRight(s.Core, "/"), s.RevocationKey, interval}
	value, _, err := revocationPolls.LoadOrNew(s.revocationSource, func() (caddy.Destructor, error) {
		ctx, cancel := context.WithCancel(context.Background())
		poll := &revocationPoll{cancel: cancel}
		go poll.run(ctx, s.client, s.revocationSource)
		return poll, nil
	})
	if err == nil {
		s.revocations = value.(*revocationPoll)
	}
	return err
}

func (s *SSO) Cleanup() error {
	if s.revocations == nil {
		return nil
	}
	_, err := revocationPolls.Delete(s.revocationSource)
	return err
}

func (p *revocationPoll) Destruct() error {
	p.cancel()
	return nil
}

func (p *revocationPoll) run(ctx context.Context, client *http.Client, source revocationSource) {
	ticker := time.NewTicker(source.interval)
	defer ticker.Stop()
	for {
		p.pull(ctx, client, source)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (p *revocationPoll) pull(ctx context.Context, client *http.Client, source revocationSource) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.core+"/gate/revocations", nil)
	if err != nil {
		return
	}
	req.Header.Set("X-Wharf-Key", source.key)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	const maxBody = 64 << 10
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	var cutoffs map[string]int64
	if err != nil || len(body) > maxBody || json.Unmarshal(body, &cutoffs) != nil || cutoffs == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	// 控制面到期即清除，网关还要覆盖本地验签接受的时钟偏差。
	keepSince := time.Now().Unix() - gateAccessTTL - CLOCK_SKEW
	for user, cutoff := range p.cutoffs {
		if cutoff > keepSince && cutoff > cutoffs[user] {
			cutoffs[user] = cutoff
		}
	}
	p.cutoffs = cutoffs
}

func (p *revocationPoll) cutoff(user string) int64 {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cutoffs[user]
}

func (s *SSO) verifyAccess(token, host string, now int64) (string, bool) {
	user, issued, ok := verify(s.key, token, host, now)
	return user, ok && issued > s.revocations.cutoff(user)
}

func (s *SSO) refreshAllowed(result *refreshResult, host string, now int64) bool {
	if s.revocations.cutoff(result.header.Get("X-Wharf-User")) == 0 {
		return true
	}
	// 续签成功的响应会缓存，同样检查里面的 access cookie。
	for _, cookie := range (&http.Response{Header: result.header}).Cookies() {
		if cookie.Name == "wharf_gate" {
			_, ok := s.verifyAccess(cookie.Value, host, now)
			return ok
		}
	}
	return false
}
