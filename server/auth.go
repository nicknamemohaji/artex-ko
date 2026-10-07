package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash"
	jwtTTL         = 7 * 24 * time.Hour
	keyChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// 인증 엔드포인트가 HTTP 응답으로 돌려주는 사용자 노출 문구다. 한국어 UI 에서 로그인·
// 비밀번호 설정이 실패하면 이 문구가 그대로 토스트로 뜨므로 한국어로 둔다. 자격 증명
// 오류 문구는 로그인 화면(web messages auth.login.errorCredential)과 표기를 맞췄다.
// token 은 기술 용어라 원문 그대로 둔다(로그·주석은 BRIEF 방침상 최하위라 손대지 않음).
const (
	authErrUnauthorized         = "인증이 필요합니다"
	authErrTokenInvalid         = "token 이 유효하지 않거나 만료되었습니다"
	authErrPasswordAlreadySet   = "비밀번호가 이미 설정되어 있습니다"
	authErrPasswordEmpty        = "비밀번호를 입력해 주세요"
	authErrNewPasswordEmpty     = "새 비밀번호를 입력해 주세요"
	authErrPasswordHash         = "비밀번호 암호화에 실패했습니다"
	authErrSaveFailedPrefix     = "저장에 실패했습니다: "
	authErrTokenGen             = "token 생성에 실패했습니다"
	authErrBadRequest           = "요청 형식이 올바르지 않습니다"
	authErrPasswordNotInit      = "비밀번호가 초기화되지 않았습니다. 먼저 비밀번호를 설정해 주세요"
	authErrCurrentPasswordWrong = "현재 비밀번호가 올바르지 않습니다"
	authErrBadCredential        = "사용자 이름 또는 비밀번호가 올바르지 않습니다"
	authErrPending              = "관리자 승인을 기다리고 있습니다"
	authErrDisabled             = "사용이 중지된 계정입니다"
	authErrAdminRequired        = "관리자 권한이 필요합니다"
)

type authClaims struct {
	Role   string `json:"role"`
	UserID int64  `json:"uid,omitempty"`
	Email  string `json:"email,omitempty"`
	jwt.RegisteredClaims
}

type oauthTransaction struct {
	verifier, nonce  string
	created, expires time.Time
}

var oauthTransactions = struct {
	sync.Mutex
	m map[string]oauthTransaction
}{m: make(map[string]oauthTransaction)}

type googleOAuthConfig struct {
	clientID, clientSecret, redirectURL, hostedDomain string
	adminEmails                                       map[string]bool
}

func loadGoogleOAuthConfig() googleOAuthConfig {
	c := googleOAuthConfig{clientID: strings.TrimSpace(os.Getenv("ARTEX_GOOGLE_CLIENT_ID")), clientSecret: strings.TrimSpace(os.Getenv("ARTEX_GOOGLE_CLIENT_SECRET")), redirectURL: strings.TrimSpace(os.Getenv("ARTEX_GOOGLE_REDIRECT_URL")), hostedDomain: strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_GOOGLE_HOSTED_DOMAIN"))), adminEmails: map[string]bool{}}
	for _, e := range strings.Split(os.Getenv("ARTEX_GOOGLE_ADMIN_EMAILS"), ",") {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			c.adminEmails[e] = true
		}
	}
	return c
}
func (c googleOAuthConfig) enabled() bool {
	return c.clientID != "" && c.clientSecret != "" && c.redirectURL != ""
}

func randomURLToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// the project base dir (next to the executable), NOT the browsable workspace root
// (dataDir) — the signing key must never be listable/downloadable via the file
// manager. Legacy installs kept it at dataDir/jwt.key; if present there and not yet
// at the new location, it is migrated (key preserved, so sessions stay valid) and
// the old file removed so it disappears from the workspace. On first run a random
// key is generated and persisted.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	path := filepath.Join(keyDir, jwtKeyFilename)
	// one-time migration out of the old in-workspace location.
	if legacy := filepath.Join(dataDir, jwtKeyFilename); legacy != path {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if data, rerr := os.ReadFile(legacy); rerr == nil {
				if werr := os.WriteFile(path, data, 0o600); werr == nil {
					_ = os.Remove(legacy)
					log.Printf("[auth] JWT key 已从 %s 迁移到 %s（移出可浏览工作区）", legacy, path)
				}
			}
		}
	}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] 新 JWT key 已写入 %s", path)
	return buf, nil
}

// signJWT issues a 7-day HS256 token for user ARTEX.
func signJWT(key []byte) (string, error) {
	return signUserJWT(key, "ARTEX", 0, "admin", "")
}
func signUserJWT(key []byte, subject string, userID int64, role, email string) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, authClaims{Role: role, UserID: userID, Email: email, RegisteredClaims: jwt.RegisteredClaims{
		Subject:   subject,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}}).SignedString(key)
}

// verifyJWT returns true when tokenStr is a valid, non-expired HS256 token.
func verifyJWT(tokenStr string, key []byte) bool {
	_, err := parseJWT(tokenStr, key)
	return err == nil
}
func parseJWT(tokenStr string, key []byte) (*authClaims, error) {
	t, err := jwt.ParseWithClaims(tokenStr, &authClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	})
	if err != nil || !t.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	c, ok := t.Claims.(*authClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims")
	}
	return c, nil
}

// extractToken reads the JWT from Authorization: Bearer header,
// artex_token cookie, or ?token= query param (for SSE connections).
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("artex_token"); err == nil && c.Value != "" {
		return c.Value
	}
	return r.URL.Query().Get("token")
}

// requireAuth wraps h with JWT validation.
// /api/auth/* and /api/health are exempt.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" {
			h.ServeHTTP(w, r)
			return
		}
		tok := extractToken(r)
		if tok == "" {
			writeErr(w, 401, authErrUnauthorized)
			return
		}
		claims, err := parseJWT(tok, s.jwtKey)
		if err != nil {
			writeErr(w, 401, authErrTokenInvalid)
			return
		}
		if claims.UserID != 0 {
			u, err := s.m.PG().AuthUserByID(claims.UserID)
			if err != nil {
				writeErr(w, 500, authErrSaveFailedPrefix+err.Error())
				return
			}
			if u == nil || u.Status == "disabled" {
				writeErr(w, 403, authErrDisabled)
				return
			}
			if u.Status != "approved" {
				writeErr(w, 403, authErrPending)
				return
			}
		}
		r = r.WithContext(context.WithValue(r.Context(), authClaimsContextKey{}, claims))
		if adminOnlyAPI(r.Method, p) && !s.requireAdmin(w, r) {
			return
		}
		h.ServeHTTP(w, r)
	})
}

func adminOnlyAPI(method, path string) bool {
	for _, prefix := range []string{"/api/update", "/api/settings", "/api/agents", "/api/triggers", "/api/tools", "/api/mcp", "/api/asset-intercept", "/api/skills", "/api/visibility", "/api/notify", "/api/logs", "/api/commands", "/api/audit", "/api/gc"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	if path == "/api/llm/profiles" && method == http.MethodGet {
		return false
	}
	if path == "/api/llm" || strings.HasPrefix(path, "/api/llm/") {
		return true
	}
	for _, prefix := range []string{"/api/intercept/rules", "/api/intercept/tool-config", "/api/intercept/judge"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	if method != http.MethodGet && (path == "/api/sync/scopesentry/datasource" || path == "/api/sync/scopesentry/sync") {
		return true
	}
	return false
}

type authClaimsContextKey struct{}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	c, _ := r.Context().Value(authClaimsContextKey{}).(*authClaims)
	if c == nil {
		var err error
		c, err = parseJWT(extractToken(r), s.jwtKey)
		if err != nil {
			writeErr(w, 401, authErrUnauthorized)
			return false
		}
	}
	if c.UserID != 0 {
		u, err := s.m.PG().AuthUserByID(c.UserID)
		if err != nil {
			writeErr(w, 500, authErrSaveFailedPrefix+err.Error())
			return false
		}
		if u == nil || u.Status != "approved" {
			writeErr(w, 403, authErrDisabled)
			return false
		}
		c.Role = u.Role
	}
	if c.Role != "admin" {
		writeErr(w, 403, authErrAdminRequired)
		return false
	}
	return true
}

// GET /api/auth/status — reports whether the admin password has been initialised.
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, _, _ := pg.GetSetting(authPassKey)
	writeJSON(w, 200, map[string]any{"initialized": hash != "", "google_oauth_enabled": loadGoogleOAuthConfig().enabled()})
}

// GET /api/auth/google starts Authorization Code + PKCE. State is bound to a
// short-lived HttpOnly cookie and a one-use server-side verifier.
func (s *Server) authGoogleStart(w http.ResponseWriter, r *http.Request) {
	c := loadGoogleOAuthConfig()
	if !c.enabled() {
		writeErr(w, 503, "Google OAuth가 설정되어 있지 않습니다")
		return
	}
	state, err := randomURLToken(32)
	if err != nil {
		writeErr(w, 500, authErrTokenGen)
		return
	}
	verifier, _ := randomURLToken(48)
	nonce, _ := randomURLToken(32)
	oauthTransactions.Lock()
	now := time.Now()
	for k, v := range oauthTransactions.m {
		if now.After(v.expires) {
			delete(oauthTransactions.m, k)
		}
	}
	if old, cookieErr := r.Cookie("artex_oauth_state"); cookieErr == nil {
		delete(oauthTransactions.m, old.Value)
	}
	if len(oauthTransactions.m) >= 1024 {
		var oldestKey string
		var oldest time.Time
		for key, tx := range oauthTransactions.m {
			if oldestKey == "" || tx.created.Before(oldest) {
				oldestKey, oldest = key, tx.created
			}
		}
		delete(oauthTransactions.m, oldestKey)
	}
	oauthTransactions.m[state] = oauthTransaction{verifier: verifier, nonce: nonce, created: now, expires: now.Add(10 * time.Minute)}
	oauthTransactions.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "artex_oauth_state", Value: state, Path: "/api/auth/google/callback", MaxAge: 600, HttpOnly: true, Secure: strings.HasPrefix(strings.ToLower(c.redirectURL), "https://"), SameSite: http.SameSiteLaxMode})
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {c.clientID}, "redirect_uri": {c.redirectURL}, "response_type": {"code"}, "scope": {"openid email profile"}, "state": {state}, "nonce": {nonce}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "prompt": {"select_account"}}
	if c.hostedDomain != "" {
		q.Set("hd", c.hostedDomain)
	}
	http.Redirect(w, r, "https://accounts.google.com/o/oauth2/v2/auth?"+q.Encode(), http.StatusFound)
}

func googlePostForm(endpoint string, form url.Values, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("google returned %d", resp.StatusCode)
	}
	return json.Unmarshal(b, out)
}

func setOAuthSessionCookie(w http.ResponseWriter, token, redirectURL string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "artex_token",
		Value:    token,
		Path:     "/",
		MaxAge:   int(jwtTTL.Seconds()),
		HttpOnly: true,
		Secure:   strings.HasPrefix(strings.ToLower(redirectURL), "https://"),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) authGoogleCallback(w http.ResponseWriter, r *http.Request) {
	c := loadGoogleOAuthConfig()
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie("artex_oauth_state")
	if err != nil || state == "" || cookie.Value != state {
		http.Redirect(w, r, "/login?oauth=invalid_state", http.StatusFound)
		return
	}
	oauthTransactions.Lock()
	tx, ok := oauthTransactions.m[state]
	delete(oauthTransactions.m, state)
	oauthTransactions.Unlock()
	if !ok || time.Now().After(tx.expires) {
		http.Redirect(w, r, "/login?oauth=expired", http.StatusFound)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "artex_oauth_state", Value: "", Path: "/api/auth/google/callback", MaxAge: -1, HttpOnly: true, Secure: strings.HasPrefix(strings.ToLower(c.redirectURL), "https://"), SameSite: http.SameSiteLaxMode})
	var tr struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := googlePostForm("https://oauth2.googleapis.com/token", url.Values{"code": {r.URL.Query().Get("code")}, "client_id": {c.clientID}, "client_secret": {c.clientSecret}, "redirect_uri": {c.redirectURL}, "grant_type": {"authorization_code"}, "code_verifier": {tx.verifier}}, &tr); err != nil {
		http.Redirect(w, r, "/login?oauth=exchange_failed", http.StatusFound)
		return
	}
	// Google's tokeninfo endpoint performs signature and expiry validation. We
	// still enforce issuer, audience and the transaction nonce here.
	ictx, icancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer icancel()
	ireq, _ := http.NewRequestWithContext(ictx, http.MethodGet, "https://oauth2.googleapis.com/tokeninfo?id_token="+url.QueryEscape(tr.IDToken), nil)
	iresp, err := http.DefaultClient.Do(ireq)
	if err != nil {
		http.Redirect(w, r, "/login?oauth=id_token_failed", 302)
		return
	}
	defer iresp.Body.Close()
	var idc struct {
		Issuer       string `json:"iss"`
		Audience     string `json:"aud"`
		Subject      string `json:"sub"`
		Nonce        string `json:"nonce"`
		HostedDomain string `json:"hd"`
	}
	if iresp.StatusCode/100 != 2 || json.NewDecoder(io.LimitReader(iresp.Body, 1<<20)).Decode(&idc) != nil || (idc.Issuer != "https://accounts.google.com" && idc.Issuer != "accounts.google.com") || idc.Audience != c.clientID || idc.Nonce != tx.nonce || idc.Subject == "" {
		http.Redirect(w, r, "/login?oauth=id_token_failed", 302)
		return
	}
	if c.hostedDomain != "" && strings.ToLower(idc.HostedDomain) != c.hostedDomain {
		http.Redirect(w, r, "/login?oauth=domain_denied", 302)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://openidconnect.googleapis.com/v1/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tr.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Redirect(w, r, "/login?oauth=userinfo_failed", 302)
		return
	}
	defer resp.Body.Close()
	var gi struct {
		Sub, Email, Name, Picture string
		EmailVerified             bool `json:"email_verified"`
	}
	if resp.StatusCode/100 != 2 || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&gi) != nil || !gi.EmailVerified {
		http.Redirect(w, r, "/login?oauth=userinfo_failed", 302)
		return
	}
	if gi.Sub != idc.Subject {
		http.Redirect(w, r, "/login?oauth=id_token_failed", 302)
		return
	}
	u, err := s.m.PG().UpsertGoogleUser(gi.Sub, gi.Email, gi.Name, gi.Picture)
	if err != nil {
		http.Redirect(w, r, "/login?oauth=save_failed", 302)
		return
	}
	if c.adminEmails[strings.ToLower(u.Email)] && u.Status == "pending" {
		u, err = s.m.PG().UpdateAuthUserAccess(u.ID, "approved", "admin")
		if err != nil || u == nil {
			http.Redirect(w, r, "/login?oauth=save_failed", 302)
			return
		}
	}
	if u.Status != "approved" {
		http.Redirect(w, r, "/login?oauth=pending", 302)
		return
	}
	tok, err := signUserJWT(s.jwtKey, u.Email, u.ID, u.Role, u.Email)
	if err != nil {
		http.Redirect(w, r, "/login?oauth=token_failed", 302)
		return
	}
	setOAuthSessionCookie(w, tok, c.redirectURL)
	http.Redirect(w, r, "/function/tasks", 302)
}

func (s *Server) authMe(w http.ResponseWriter, r *http.Request) {
	c, err := parseJWT(extractToken(r), s.jwtKey)
	if err != nil {
		writeErr(w, 401, authErrUnauthorized)
		return
	}
	if c.UserID != 0 {
		u, e := s.m.PG().AuthUserByID(c.UserID)
		if e != nil {
			writeErr(w, 500, e.Error())
			return
		}
		if u == nil || u.Status != "approved" {
			writeErr(w, 403, authErrDisabled)
			return
		}
		c.Role = u.Role
	}
	writeJSON(w, 200, map[string]any{"subject": c.Subject, "email": c.Email, "role": c.Role, "user_id": c.UserID})
}
func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	secure := strings.HasPrefix(strings.ToLower(loadGoogleOAuthConfig().redirectURL), "https://")
	http.SetCookie(w, &http.Cookie{Name: "artex_token", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
func (s *Server) authAdminUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	users, err := s.m.PG().ListAuthUsers()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"users": users})
}
func (s *Server) authAdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, authErrBadRequest)
		return
	}
	var q struct{ Status, Role string }
	if decode(r, &q) != nil || (q.Status != "pending" && q.Status != "approved" && q.Status != "disabled") || (q.Role != "admin" && q.Role != "user") {
		writeErr(w, 400, authErrBadRequest)
		return
	}
	claims, _ := parseJWT(extractToken(r), s.jwtKey)
	if claims != nil && claims.UserID == id && (q.Status != "approved" || q.Role != "admin") {
		writeErr(w, http.StatusConflict, "자기 자신의 관리자 권한이나 사용 상태를 해제할 수 없습니다")
		return
	}
	u, err := s.m.PG().UpdateAuthUserAccess(id, q.Status, q.Role)
	if err != nil {
		if errors.Is(err, db.ErrLastApprovedAdmin) {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	if u == nil {
		writeErr(w, 404, "사용자를 찾을 수 없습니다")
		return
	}
	writeJSON(w, 200, u)
}

// POST /api/auth/init — sets the password for the first time; rejected if already set.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	// Once OAuth is configured, leaving the public first-run password endpoint
	// available would let an unauthenticated visitor claim the legacy admin.
	if loadGoogleOAuthConfig().enabled() {
		writeErr(w, 403, "Google OAuth가 설정된 상태에서는 공개 비밀번호 초기화를 사용할 수 없습니다")
		return
	}
	existing, _, _ := pg.GetSetting(authPassKey)
	if existing != "" {
		writeErr(w, 403, authErrPasswordAlreadySet)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil || req.Password == "" {
		writeErr(w, 400, authErrPasswordEmpty)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, authErrPasswordHash)
		return
	}
	if err := pg.SetSetting(authPassKey, string(hash)); err != nil {
		writeErr(w, 500, authErrSaveFailedPrefix+err.Error())
		return
	}
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		writeErr(w, 500, authErrTokenGen)
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/change-password — changes the admin password. Requires a valid
// token (this route is under /api/auth/* which requireAuth exempts, so the token
// is validated here) AND the current password.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, authErrBadRequest)
		return
	}
	if req.NewPassword == "" {
		writeErr(w, 400, authErrNewPasswordEmpty)
		return
	}
	hash, ok, _ := pg.GetSetting(authPassKey)
	if !ok || hash == "" {
		writeErr(w, 403, authErrPasswordNotInit)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)); err != nil {
		writeErr(w, 401, authErrCurrentPasswordWrong)
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, authErrPasswordHash)
		return
	}
	if err := pg.SetSetting(authPassKey, string(newHash)); err != nil {
		writeErr(w, 500, authErrSaveFailedPrefix+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// POST /api/auth/login — validates username/password and returns a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, authErrBadRequest)
		return
	}
	if req.Username != "ARTEX" {
		writeErr(w, 401, authErrBadCredential)
		return
	}
	hash, ok, _ := pg.GetSetting(authPassKey)
	if !ok || hash == "" {
		writeErr(w, 403, authErrPasswordNotInit)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		writeErr(w, 401, authErrBadCredential)
		return
	}
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		writeErr(w, 500, authErrTokenGen)
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}
