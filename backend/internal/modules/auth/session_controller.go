package auth

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/aldoexpert/mikrotik-wireguard/internal/config"
	"github.com/aldoexpert/mikrotik-wireguard/internal/core"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/store"
	"github.com/aldoexpert/mikrotik-wireguard/internal/middleware"
)

var usernameRegexp = regexp.MustCompile(`^\w[\w\-.]*$`)

type SessionController struct {
	cfg      *config.App
	db       store.IStore
	registry *core.Registry
}

func NewSessionController(cfg *config.App, db store.IStore, registry *core.Registry) *SessionController {
	return &SessionController{cfg: cfg, db: db, registry: registry}
}

type loginPayload struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	RememberMe bool   `json:"remember_me"`
}

type loginResponse struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Admin    bool   `json:"admin"`
}

// Login validates credentials and issues a JWT session token.
func (c *SessionController) Login(w http.ResponseWriter, r *http.Request, params []string) {
	var payload loginPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		core.BadRequest(w, "Invalid login data")
		return
	}

	if !usernameRegexp.MatchString(payload.Username) {
		core.BadRequest(w, "Invalid username")
		return
	}

	dbUser, err := c.db.GetUserByName(payload.Username)
	if err != nil {
		core.Unauthorized(w, "Invalid username or password")
		return
	}

	usernameMatches := subtle.ConstantTimeCompare([]byte(payload.Username), []byte(dbUser.Username)) == 1

	var passwordMatches bool
	if dbUser.PasswordHash != "" {
		passwordMatches, err = library.VerifyHash(dbUser.PasswordHash, payload.Password)
		if err != nil {
			core.InternalError(w, "Could not verify the password", err)
			return
		}
	} else {
		passwordMatches = subtle.ConstantTimeCompare([]byte(payload.Password), []byte(dbUser.Password)) == 1
	}

	if !usernameMatches || !passwordMatches {
		core.Unauthorized(w, "Invalid username or password")
		return
	}

	userHash := library.GetDBUserCRC32(dbUser)
	token, err := library.NewToken(c.cfg.JWTSecret, dbUser.Username, dbUser.Admin, userHash, payload.RememberMe, c.cfg.JWTExpiryHours, c.cfg.SessionMaxDurationS)
	if err != nil {
		core.InternalError(w, "Could not create the session", err)
		return
	}

	core.Success(w, "Login successful", loginResponse{Token: token, Username: dbUser.Username, Admin: dbUser.Admin})
}

// Logout is a no-op on the server: JWT sessions are stateless, so the
// frontend simply discards its token. Kept as an endpoint for symmetry and
// so a future server-side token blacklist can be added without an API change.
func (c *SessionController) Logout(w http.ResponseWriter, r *http.Request, params []string) {
	core.Success(w, "Logged out successfully", nil)
}

// Profile returns the currently authenticated user's own record.
func (c *SessionController) Profile(w http.ResponseWriter, r *http.Request, params []string) {
	username := middleware.CurrentUsername(r)
	user, err := c.db.GetUserByName(username)
	if err != nil {
		core.NotFound(w, "User not found")
		return
	}
	user.Password = ""
	user.PasswordHash = ""
	core.Success(w, "", user)
}

// Menu returns every menu group registered by the app's modules (see
// core.Registry.RegisterMenu), with admin-only items stripped out for
// non-admin callers -- the frontend's panel renders this directly instead
// of hardcoding navigation per role.
func (c *SessionController) Menu(w http.ResponseWriter, r *http.Request, params []string) {
	isAdmin := middleware.IsAdmin(r)

	groups := c.registry.GetMenus()
	visible := make([]core.MenuGroup, 0, len(groups))
	for _, group := range groups {
		items := make([]core.MenuItem, 0, len(group.List))
		for _, item := range group.List {
			if item.Admin && !isAdmin {
				continue
			}
			items = append(items, item)
		}
		if len(items) == 0 {
			continue
		}
		group.List = items
		visible = append(visible, group)
	}

	core.SuccessList(w, "", visible)
}
