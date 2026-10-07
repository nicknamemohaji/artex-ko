package db

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

var ErrLastApprovedAdmin = errors.New("마지막 승인 관리자는 강등하거나 사용 중지할 수 없습니다")

type AuthUser struct {
	ID          int64      `json:"id"`
	Provider    string     `json:"provider"`
	ProviderID  string     `json:"-"`
	Email       string     `json:"email"`
	Name        string     `json:"name"`
	AvatarURL   string     `json:"avatar_url"`
	Role        string     `json:"role"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

func scanAuthUser(row interface{ Scan(...any) error }) (*AuthUser, error) {
	var u AuthUser
	err := row.Scan(&u.ID, &u.Provider, &u.ProviderID, &u.Email, &u.Name, &u.AvatarURL, &u.Role, &u.Status, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

const authUserColumns = `id,provider,provider_id,email,name,avatar_url,role,status,created_at,updated_at,last_login_at`

func (d *DB) UpsertGoogleUser(providerID, email, name, avatar string) (*AuthUser, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	return scanAuthUser(d.QueryRow(`INSERT INTO auth_users(provider,provider_id,email,name,avatar_url,last_login_at)
		VALUES('google',$1,$2,$3,$4,now())
		ON CONFLICT(provider,provider_id) DO UPDATE SET email=excluded.email,name=excluded.name,
		avatar_url=excluded.avatar_url,last_login_at=now(),updated_at=now()
		RETURNING `+authUserColumns, providerID, email, name, avatar))
}

func (d *DB) AuthUserByID(id int64) (*AuthUser, error) {
	u, err := scanAuthUser(d.QueryRow(`SELECT `+authUserColumns+` FROM auth_users WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

func (d *DB) ListAuthUsers() ([]AuthUser, error) {
	rows, err := d.Query(`SELECT ` + authUserColumns + ` FROM auth_users ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuthUser
	for rows.Next() {
		u, err := scanAuthUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (d *DB) UpdateAuthUserAccess(id int64, status, role string) (*AuthUser, error) {
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var currentStatus, currentRole string
	if err = tx.QueryRow(`SELECT status,role FROM auth_users WHERE id=$1 FOR UPDATE`, id).Scan(&currentStatus, &currentRole); errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if currentStatus == "approved" && currentRole == "admin" && (status != "approved" || role != "admin") {
		if _, err = tx.Exec(`SELECT pg_advisory_xact_lock(7337741011)`); err != nil {
			return nil, err
		}
		var n int
		if err = tx.QueryRow(`SELECT count(*) FROM auth_users WHERE status='approved' AND role='admin'`).Scan(&n); err != nil {
			return nil, err
		}
		if n <= 1 {
			return nil, ErrLastApprovedAdmin
		}
	}
	u, err := scanAuthUser(tx.QueryRow(`UPDATE auth_users SET status=$2,role=$3,updated_at=now() WHERE id=$1 RETURNING `+authUserColumns, id, status, role))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return u, nil
}
