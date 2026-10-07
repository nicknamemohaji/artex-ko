package server

import (
	"context"
	"fmt"
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

func TestRegularUserCannotAccessPhaseOneAdminResources(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil || m.PG() == nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer m.Close()
	u, err := m.PG().UpsertGoogleUser("phase-one-policy", "phase-one@example.com", "User", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.PG().Exec(`DELETE FROM auth_users WHERE id=$1`, u.ID) })
	if _, err = m.PG().UpdateAuthUserAccess(u.ID, "approved", "user"); err != nil {
		t.Fatal(err)
	}
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	tok, _ := signUserJWT(s.jwtKey, u.Email, u.ID, "user", u.Email)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/workspace/list"},
		{http.MethodGet, "/api/traffic"},
		{http.MethodGet, "/api/tokens/daily"},
		{http.MethodPost, "/api/task-templates"},
		{http.MethodGet, "/api/exploration/findings"},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`))
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s status=%d, want 403", tc.method, tc.path, w.Code)
		}
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
	for _, p := range []string{"/api/update/check", "/api/llm", "/api/llm/profiles/active", "/api/settings", "/api/agents/x", "/api/triggers/1", "/api/tools", "/api/mcp", "/api/intercept/rules", "/api/intercept/judge", "/api/skills", "/api/logs/stream", "/api/workspace/list", "/api/traffic", "/api/assets", "/api/companies", "/api/exploration/findings", "/api/tokens/daily"} {
		if !adminOnlyAPI(http.MethodGet, p) {
			t.Errorf("not protected: %s", p)
		}
	}
	for _, p := range []string{"/api/tasks", "/api/chat", "/api/llm/profiles", "/api/task-categories", "/api/task-templates"} {
		if adminOnlyAPI(http.MethodGet, p) {
			t.Errorf("unexpected admin-only: %s", p)
		}
	}
	for _, p := range []string{"/api/sync/scopesentry/projects"} {
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

func TestOAuthTransactionGlobalCapEvictsOldest(t *testing.T) {
	t.Setenv("ARTEX_GOOGLE_CLIENT_ID", "id")
	t.Setenv("ARTEX_GOOGLE_CLIENT_SECRET", "secret")
	t.Setenv("ARTEX_GOOGLE_REDIRECT_URL", "https://artex.example/api/auth/google/callback")
	oauthTransactions.Lock()
	old := oauthTransactions.m
	oauthTransactions.m = make(map[string]oauthTransaction, 1024)
	for i := 0; i < 1024; i++ {
		oauthTransactions.m[fmt.Sprint(i)] = oauthTransaction{created: time.Now().Add(time.Duration(i) * time.Second), expires: time.Now().Add(time.Hour)}
	}
	oauthTransactions.Unlock()
	defer func() { oauthTransactions.Lock(); oauthTransactions.m = old; oauthTransactions.Unlock() }()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/google", nil)
	(&Server{}).authGoogleStart(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("status=%d", w.Code)
	}
	oauthTransactions.Lock()
	defer oauthTransactions.Unlock()
	if len(oauthTransactions.m) != 1024 {
		t.Fatalf("transactions=%d", len(oauthTransactions.m))
	}
	if _, exists := oauthTransactions.m["0"]; exists {
		t.Fatal("oldest transaction was not evicted")
	}
}
