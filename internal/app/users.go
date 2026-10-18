package app

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
	APIKey       string `json:"api_key"`
	Role         string `json:"role"`   // "admin" or "user"
	Status       string `json:"status"` // "active" or "disabled"
	CreatedAt    int64  `json:"created_at"`
}

type userCtxKeyType struct{}

var userCtxKey = userCtxKeyType{}

func withUser(ctx context.Context, u *User) context.Context {
	if u == nil {
		return ctx
	}
	return context.WithValue(ctx, userCtxKey, u)
}

func userFromContext(ctx context.Context) *User {
	if ctx == nil {
		return nil
	}
	if u, ok := ctx.Value(userCtxKey).(*User); ok {
		return u
	}
	return nil
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func authenticateUser(username, password string) (*User, error) {
	u := getUserByUsername(username)
	if u == nil {
		return nil, fmt.Errorf("user not found")
	}
	if u.Status != "active" {
		return nil, fmt.Errorf("account is disabled")
	}
	if !checkPassword(u.PasswordHash, password) {
		return nil, fmt.Errorf("invalid password")
	}
	return u, nil
}

var usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]{3,32}$`)

func createUser(username, password, role string) (*User, error) {
	username = strings.TrimSpace(username)
	if !usernameRe.MatchString(username) {
		return nil, fmt.Errorf("username must be 3-32 characters and only contain letters, numbers, _, -, .")
	}
	if len(password) < 6 {
		return nil, fmt.Errorf("password must be at least 6 characters")
	}
	if role != "admin" && role != "user" {
		role = "user"
	}

	// Check if username already exists
	if existing := getUserByUsername(username); existing != nil {
		return nil, fmt.Errorf("username %q is already taken", username)
	}

	pwHash, err := hashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	apiKey := newAPIKey()
	now := time.Now().Unix()

	id, err := insertID(
		`INSERT INTO users (username, password_hash, api_key, role, status, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		username, pwHash, apiKey, role, "active", now,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert user: %w", err)
	}

	return &User{
		ID:           id,
		Username:     username,
		PasswordHash: pwHash,
		APIKey:       apiKey,
		Role:         role,
		Status:       "active",
		CreatedAt:    now,
	}, nil
}

func getUserByUsername(username string) *User {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil
	}
	var u User
	err := getDB().QueryRow(
		`SELECT id, username, password_hash, api_key, role, status, created_at FROM users WHERE username=?`,
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.APIKey, &u.Role, &u.Status, &u.CreatedAt)
	if err != nil {
		return nil
	}
	return &u
}

func getUserByID(id int64) *User {
	if id <= 0 {
		return nil
	}
	var u User
	err := getDB().QueryRow(
		`SELECT id, username, password_hash, api_key, role, status, created_at FROM users WHERE id=?`,
		id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.APIKey, &u.Role, &u.Status, &u.CreatedAt)
	if err != nil {
		return nil
	}
	return &u
}

func getUserByAPIKey(key string) *User {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	var u User
	err := getDB().QueryRow(
		`SELECT id, username, password_hash, api_key, role, status, created_at FROM users WHERE api_key=? AND status='active'`,
		key,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.APIKey, &u.Role, &u.Status, &u.CreatedAt)
	if err != nil {
		return nil
	}
	return &u
}

func listUsers() []*User {
	rows, err := getDB().Query(
		`SELECT id, username, password_hash, api_key, role, status, created_at FROM users ORDER BY id ASC`,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.APIKey, &u.Role, &u.Status, &u.CreatedAt); err != nil {
			continue
		}
		users = append(users, &u)
	}
	return users
}

func rotateUserAPIKey(id int64) (string, error) {
	newKey := newAPIKey()
	_, err := getDB().Exec(`UPDATE users SET api_key=? WHERE id=?`, newKey, id)
	if err != nil {
		return "", err
	}
	// If this user is admin, also sync runtime API key
	if u := getUserByID(id); u != nil && u.Role == "admin" && !apiKeyLocked {
		apiKeyRuntime.Store(newKey)
		_ = kvSet("api_key", newKey)
	}
	return newKey, nil
}

func setUserAPIKey(id int64, newKey string) error {
	newKey = strings.TrimSpace(newKey)
	if len(newKey) < 20 {
		return errMsg("API key too short (min 20 chars)")
	}
	_, err := getDB().Exec(`UPDATE users SET api_key=? WHERE id=?`, newKey, id)
	if err != nil {
		return err
	}
	if u := getUserByID(id); u != nil && u.Role == "admin" && !apiKeyLocked {
		apiKeyRuntime.Store(newKey)
		_ = kvSet("api_key", newKey)
	}
	return nil
}

var (
	adminInitMu sync.Mutex
	cachedAdmin *User
)

// initDefaultAdmin guarantees an admin user exists and existing cookies/keys are properly attached.
func initDefaultAdmin() *User {
	adminInitMu.Lock()
	defer adminInitMu.Unlock()

	if cachedAdmin != nil {
		return cachedAdmin
	}

	// Look for an existing admin user
	var u User
	err := getDB().QueryRow(
		`SELECT id, username, password_hash, api_key, role, status, created_at FROM users WHERE role='admin' ORDER BY id ASC LIMIT 1`,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.APIKey, &u.Role, &u.Status, &u.CreatedAt)

	if err == nil {
		cachedAdmin = &u
	} else if err == sql.ErrNoRows {
		// Create default admin user
		adminPass := cfg.AdminToken
		if adminPass == "" {
			adminPass = "admin123"
		}
		pwHash, _ := hashPassword(adminPass)
		k := getAPIKey()
		if k == "" {
			k = newAPIKey()
		}
		now := time.Now().Unix()
		id, insErr := insertID(
			`INSERT INTO users (username, password_hash, api_key, role, status, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
			"admin", pwHash, k, "admin", "active", now,
		)
		if insErr == nil {
			cachedAdmin = &User{
				ID:           id,
				Username:     "admin",
				PasswordHash: pwHash,
				APIKey:       k,
				Role:         "admin",
				Status:       "active",
				CreatedAt:    now,
			}
			logf("[users] created default admin user (id=%d, username=admin)", id)
		}
	}

	if cachedAdmin != nil {
		// Migrate legacy accounts and requests that have user_id = 0 to default admin
		_, _ = getDB().Exec(`UPDATE accounts SET user_id=? WHERE user_id=0`, cachedAdmin.ID)
		_, _ = getDB().Exec(`UPDATE requests SET user_id=? WHERE user_id=0`, cachedAdmin.ID)
	}
	return cachedAdmin
}
