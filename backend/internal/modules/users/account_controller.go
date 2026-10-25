package users

import (
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/aldoexpert/mikrotik-wireguard/internal/config"
	"github.com/aldoexpert/mikrotik-wireguard/internal/core"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/store"
	"github.com/aldoexpert/mikrotik-wireguard/internal/middleware"
	"github.com/aldoexpert/mikrotik-wireguard/internal/model"
)

var usernameRegexp = regexp.MustCompile(`^\w[\w\-.]*$`)

type AccountController struct {
	cfg *config.App
	db  store.IStore
}

func NewAccountController(cfg *config.App, db store.IStore) *AccountController {
	return &AccountController{cfg: cfg, db: db}
}

func sanitize(u model.User) model.User {
	u.Password = ""
	u.PasswordHash = ""
	return u
}

// List returns every account. Admin only.
func (c *AccountController) List(w http.ResponseWriter, r *http.Request, params []string) {
	list, err := c.db.GetUsers()
	if err != nil {
		core.InternalError(w, "Could not get the user list", err)
		return
	}
	for i := range list {
		list[i] = sanitize(list[i])
	}
	core.SuccessList(w, "", list)
}

// Get returns a single account. A manager may only fetch their own record.
func (c *AccountController) Get(w http.ResponseWriter, r *http.Request, params []string) {
	if len(params) < 1 {
		core.BadRequest(w, "Username is required")
		return
	}
	username := params[0]

	if !usernameRegexp.MatchString(username) {
		core.BadRequest(w, "Invalid username")
		return
	}
	if !middleware.IsAdmin(r) && username != middleware.CurrentUsername(r) {
		core.Forbidden(w, "A manager cannot access another user's data")
		return
	}

	user, err := c.db.GetUserByName(username)
	if err != nil {
		core.NotFound(w, "User not found")
		return
	}
	core.Success(w, "", sanitize(user))
}

type createPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Admin    bool   `json:"admin"`
}

// Create adds a new account. Admin only.
func (c *AccountController) Create(w http.ResponseWriter, r *http.Request, params []string) {
	var payload createPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		core.BadRequest(w, "Invalid data")
		return
	}

	if payload.Username == "" || !usernameRegexp.MatchString(payload.Username) {
		core.BadRequest(w, "Invalid username")
		return
	}
	if _, err := c.db.GetUserByName(payload.Username); err == nil {
		core.BadRequest(w, "Username already in use")
		return
	}

	hash, err := library.HashPassword(payload.Password)
	if err != nil {
		core.InternalError(w, "Could not hash the password", err)
		return
	}

	user := model.User{Username: payload.Username, PasswordHash: hash, Admin: payload.Admin}
	if err := c.db.SaveUser(user); err != nil {
		core.InternalError(w, "Could not save the user", err)
		return
	}

	core.Success(w, "User created successfully", sanitize(user))
}

type updatePayload struct {
	Username         string `json:"username"`
	Password         string `json:"password"`
	PreviousUsername string `json:"previous_username"`
	Admin            bool   `json:"admin"`
}

type updateResponse struct {
	Token string `json:"token,omitempty"`
}

// Update edits an account. A manager may only edit their own record (and
// may not grant themselves admin). When the caller edits their own account,
// a fresh JWT is returned so the frontend can keep the session alive even
// though the embedded user checksum just changed.
func (c *AccountController) Update(w http.ResponseWriter, r *http.Request, params []string) {
	var payload updatePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		core.BadRequest(w, "Invalid data")
		return
	}

	currentUser := middleware.CurrentUsername(r)
	isAdmin := middleware.IsAdmin(r)

	if !isAdmin && payload.PreviousUsername != currentUser {
		core.Forbidden(w, "A manager cannot change another user's data")
		return
	}
	if !isAdmin {
		payload.Admin = false
	}
	if !usernameRegexp.MatchString(payload.PreviousUsername) {
		core.BadRequest(w, "Invalid username")
		return
	}

	user, err := c.db.GetUserByName(payload.PreviousUsername)
	if err != nil {
		core.NotFound(w, err.Error())
		return
	}

	if payload.Username == "" || !usernameRegexp.MatchString(payload.Username) {
		core.BadRequest(w, "Invalid username")
		return
	}
	user.Username = payload.Username

	if payload.Username != payload.PreviousUsername {
		if _, err := c.db.GetUserByName(payload.Username); err == nil {
			core.BadRequest(w, "Username already in use")
			return
		}
	}

	if payload.Password != "" {
		hash, err := library.HashPassword(payload.Password)
		if err != nil {
			core.InternalError(w, "Could not hash the password", err)
			return
		}
		user.PasswordHash = hash
	}

	if payload.PreviousUsername != currentUser {
		user.Admin = payload.Admin
	}

	if err := c.db.DeleteUser(payload.PreviousUsername); err != nil {
		core.InternalError(w, "Could not update the user", err)
		return
	}
	if err := c.db.SaveUser(user); err != nil {
		core.InternalError(w, "Could not update the user", err)
		return
	}

	resp := updateResponse{}
	if payload.PreviousUsername == currentUser {
		token, err := library.NewToken(c.cfg.JWTSecret, user.Username, user.Admin, library.GetDBUserCRC32(user), false, c.cfg.JWTExpiryHours, c.cfg.SessionMaxDurationS)
		if err == nil {
			resp.Token = token
		}
	}

	core.Success(w, "User updated successfully", resp)
}

type deletePayload struct {
	Username string `json:"username"`
}

// Delete removes an account. Admin only, and cannot delete yourself.
func (c *AccountController) Delete(w http.ResponseWriter, r *http.Request, params []string) {
	var payload deletePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		core.BadRequest(w, "Invalid data")
		return
	}

	if !usernameRegexp.MatchString(payload.Username) {
		core.BadRequest(w, "Invalid username")
		return
	}
	if payload.Username == middleware.CurrentUsername(r) {
		core.Forbidden(w, "A user cannot delete themselves")
		return
	}

	if err := c.db.DeleteUser(payload.Username); err != nil {
		core.InternalError(w, "Could not delete the user from the database", err)
		return
	}

	core.Success(w, "User deleted successfully", nil)
}
