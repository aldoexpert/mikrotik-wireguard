package library

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims carried inside the session JWT. UserHash lets us invalidate every
// outstanding token for a user as soon as their record changes (password
// change, admin flag change, deletion) -- see cache.go.
type Claims struct {
	Username   string `json:"username"`
	Admin      bool   `json:"admin"`
	UserHash   uint32 `json:"user_hash"`
	RememberMe bool   `json:"remember_me"`
	jwt.RegisteredClaims
}

// NewToken signs a session JWT for username. When rememberMe is true the
// token lives up to sessionMaxDurationS (long-lived "remember me" session),
// otherwise it uses the short expiryHours lifetime.
func NewToken(secret [64]byte, username string, admin bool, userHash uint32, rememberMe bool, expiryHours int, sessionMaxDurationS int64) (string, error) {
	now := time.Now().UTC()
	expiry := now.Add(time.Duration(expiryHours) * time.Hour)
	if rememberMe {
		expiry = now.Add(time.Duration(sessionMaxDurationS) * time.Second)
	}

	claims := Claims{
		Username:   username,
		Admin:      admin,
		UserHash:   userHash,
		RememberMe: rememberMe,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiry),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(secret[:])
}

// ParseToken validates tokenString and returns its claims.
func ParseToken(secret [64]byte, tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return secret[:], nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}
