package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGoogleOAuthStartUsesStateNonceAndPKCE(t *testing.T) {
	t.Setenv("ARTEX_GOOGLE_CLIENT_ID", "client-id")
	t.Setenv("ARTEX_GOOGLE_CLIENT_SECRET", "client-secret")
	t.Setenv("ARTEX_GOOGLE_REDIRECT_URL", "https://artex.example/api/auth/google/callback")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/google", nil)
	(&Server{}).authGoogleStart(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	for _, key := range []string{"state", "nonce", "code_challenge"} {
		if q.Get(key) == "" {
			t.Fatalf("missing %s", key)
		}
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("PKCE method=%q", q.Get("code_challenge_method"))
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("unsafe state cookie: %#v", cookies)
	}
	if cookies[0].Value != q.Get("state") {
		t.Fatal("state cookie does not bind authorization request")
	}
	oauthTransactions.Lock()
	tx := oauthTransactions.m[q.Get("state")]
	oauthTransactions.Unlock()
	if tx.nonce != q.Get("nonce") || tx.verifier == "" {
		t.Fatal("server transaction missing nonce/verifier")
	}
}

func TestOAuthSessionCookieSecurity(t *testing.T) {
	rec := httptest.NewRecorder()
	setOAuthSessionCookie(rec, "secret-token", "https://artex.example/api/auth/google/callback")
	c := rec.Result().Cookies()[0]
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Fatalf("unsafe cookie: %#v", c)
	}
}

func TestJWTStrictlyRequiresHS256AndCarriesRole(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	tok, err := signUserJWT(key, "user@example.com", 42, "user", "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	c, err := parseJWT(tok, key)
	if err != nil || c.UserID != 42 || c.Role != "user" {
		t.Fatalf("claims=%#v err=%v", c, err)
	}
	bad, err := jwt.NewWithClaims(jwt.SigningMethodHS384, c).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if verifyJWT(bad, key) {
		t.Fatal("accepted non-HS256 token")
	}
}

func TestOAuthApprovalAndDisableTakeEffectImmediately(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil || m.PG() == nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer m.Close()
	u, err := m.PG().UpsertGoogleUser("server-oauth-approval-test", "server-oauth-approval@example.com", "Test", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.PG().Exec(`DELETE FROM auth_users WHERE id=$1`, u.ID) })
	_, _ = m.PG().UpdateAuthUserAccess(u.ID, "pending", "user")
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	h := s.Handler()
	tok, err := signUserJWT(s.jwtKey, u.Email, u.ID, "user", u.Email)
	if err != nil {
		t.Fatal(err)
	}
	request := func() int {
		r := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if got := request(); got != http.StatusForbidden {
		t.Fatalf("pending status=%d", got)
	}
	if _, err = m.PG().UpdateAuthUserAccess(u.ID, "approved", "user"); err != nil {
		t.Fatal(err)
	}
	if got := request(); got != http.StatusOK {
		t.Fatalf("approved status=%d", got)
	}
	if _, err = m.PG().UpdateAuthUserAccess(u.ID, "disabled", "user"); err != nil {
		t.Fatal(err)
	}
	if got := request(); got != http.StatusForbidden {
		t.Fatalf("disabled status=%d", got)
	}
}

func TestRegularUserCannotUseAdminAPI(t *testing.T) {
	key := []byte(strings.Repeat("a", 32))
	tok, err := signUserJWT(key, "user@example.com", 0, "user", "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{jwtKey: key}
	r := httptest.NewRequest(http.MethodGet, "/api/auth/admin/users", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	if s.requireAdmin(w, r) {
		t.Fatal("regular user accepted as admin")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestAdminOnlyAPIBoundaries(t *testing.T) {
	for _, p := range []string{"/api/update/check", "/api/llm", "/api/llm/profiles/active", "/api/settings", "/api/agents/x", "/api/triggers/1", "/api/tools", "/api/mcp", "/api/intercept/rules", "/api/intercept/judge", "/api/skills", "/api/logs/stream"} {
		if !adminOnlyAPI(http.MethodGet, p) {
			t.Errorf("not protected: %s", p)
		}
	}
	for _, p := range []string{"/api/tasks", "/api/chat", "/api/assets", "/api/intercept/pending", "/api/intercept/pending/1", "/api/intercept/history", "/api/llm/profiles"} {
		if adminOnlyAPI(http.MethodGet, p) {
			t.Errorf("unexpected admin-only: %s", p)
		}
	}
	for _, p := range []string{"/api/intercept/pending/1/decide", "/api/sync/scopesentry/projects"} {
		if adminOnlyAPI(http.MethodPost, p) {
			t.Errorf("approved-user flow blocked: %s", p)
		}
	}
	for _, p := range []string{"/api/sync/scopesentry/datasource", "/api/sync/scopesentry/sync", "/api/llm/profiles"} {
		if !adminOnlyAPI(http.MethodPost, p) {
			t.Errorf("mutation not protected: %s", p)
		}
	}
}

func TestLogoutClearsHttpOnlyCookie(t *testing.T) {
	t.Setenv("ARTEX_GOOGLE_REDIRECT_URL", "https://artex.example/api/auth/google/callback")
	w := httptest.NewRecorder()
	(&Server{}).authLogout(w, httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil))
	c := w.Result().Cookies()[0]
	if c.Name != "artex_token" || c.MaxAge != -1 || !c.HttpOnly || !c.Secure || c.Path != "/" {
		t.Fatalf("cookie=%#v", c)
	}
}

func TestOAuthTransactionPerClientRateLimit(t *testing.T) {
	t.Setenv("ARTEX_GOOGLE_CLIENT_ID", "id")
	t.Setenv("ARTEX_GOOGLE_CLIENT_SECRET", "secret")
	t.Setenv("ARTEX_GOOGLE_REDIRECT_URL", "https://artex.example/api/auth/google/callback")
	oauthTransactions.Lock()
	old := oauthTransactions.m
	oauthTransactions.m = make(map[string]oauthTransaction, 10)
	for i := 0; i < 10; i++ {
		oauthTransactions.m[string(rune('a'+i))] = oauthTransaction{client: "192.0.2.1", created: time.Now(), expires: time.Now().Add(time.Minute)}
	}
	oauthTransactions.Unlock()
	defer func() { oauthTransactions.Lock(); oauthTransactions.m = old; oauthTransactions.Unlock() }()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/google", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	(&Server{}).authGoogleStart(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d", w.Code)
	}
	if w.Header().Get("Retry-After") != "60" {
		t.Fatalf("Retry-After=%q", w.Header().Get("Retry-After"))
	}
}
