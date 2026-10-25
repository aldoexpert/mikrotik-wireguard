package wireguard

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/aldoexpert/mikrotik-wireguard/internal/core"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/store"
	"github.com/aldoexpert/mikrotik-wireguard/internal/model"
)

type SettingsController struct {
	db store.IStore
}

func NewSettingsController(db store.IStore) *SettingsController {
	return &SettingsController{db: db}
}

// Get returns the global (server-wide) WireGuard settings.
func (c *SettingsController) Get(w http.ResponseWriter, r *http.Request, params []string) {
	settings, err := c.db.GetGlobalSettings()
	if err != nil {
		core.InternalError(w, "Could not get the global settings", err)
		return
	}
	core.Success(w, "", settings)
}

// Update edits the global (server-wide) WireGuard settings.
func (c *SettingsController) Update(w http.ResponseWriter, r *http.Request, params []string) {
	var settings model.GlobalSetting
	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		core.BadRequest(w, "Invalid data")
		return
	}

	if !library.ValidateIPAddressList(settings.DNSServers) {
		core.BadRequest(w, "Invalid DNS server address")
		return
	}

	settings.UpdatedAt = time.Now().UTC()
	if err := c.db.SaveGlobalSettings(settings); err != nil {
		core.InternalError(w, "Could not save the global settings", err)
		return
	}

	core.Success(w, "Global settings updated successfully", nil)
}
