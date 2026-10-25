package wireguard

import (
	"encoding/json"
	"net/http"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/aldoexpert/mikrotik-wireguard/internal/core"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/mikrotik"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/store"
	"github.com/aldoexpert/mikrotik-wireguard/internal/model"
)

type ServerController struct {
	db             store.IStore
	wgConfTemplate string
}

func NewServerController(db store.IStore, wgConfTemplate string) *ServerController {
	return &ServerController{db: db, wgConfTemplate: wgConfTemplate}
}

// Get returns the server's interface settings and key pair.
func (c *ServerController) Get(w http.ResponseWriter, r *http.Request, params []string) {
	server, err := c.db.GetServer()
	if err != nil {
		core.InternalError(w, "Could not get the server configuration", err)
		return
	}
	core.Success(w, "", server)
}

// UpdateInterfaces updates the server's [Interface] addresses/port/scripts.
func (c *ServerController) UpdateInterfaces(w http.ResponseWriter, r *http.Request, params []string) {
	var serverInterface model.ServerInterface
	if err := json.NewDecoder(r.Body).Decode(&serverInterface); err != nil {
		core.BadRequest(w, "Invalid data")
		return
	}

	if !library.ValidateServerAddresses(serverInterface.Addresses) {
		core.BadRequest(w, "Interface IP address must be in CIDR format")
		return
	}

	serverInterface.UpdatedAt = time.Now().UTC()
	if err := c.db.SaveServerInterface(serverInterface); err != nil {
		core.InternalError(w, "Could not save the server interface", err)
		return
	}

	core.Success(w, "Server interface updated successfully", nil)
}

// UpdateKeyPair generates and stores a fresh server key pair.
func (c *ServerController) UpdateKeyPair(w http.ResponseWriter, r *http.Request, params []string) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		core.InternalError(w, "Could not generate a WireGuard key pair", err)
		return
	}

	serverKeyPair := model.ServerKeypair{
		PrivateKey: key.String(),
		PublicKey:  key.PublicKey().String(),
		UpdatedAt:  time.Now().UTC(),
	}

	if err := c.db.SaveServerKeyPair(serverKeyPair); err != nil {
		core.InternalError(w, "Could not save the WireGuard key pair", err)
		return
	}

	core.Success(w, "Server key pair updated successfully", serverKeyPair)
}

// ApplyConfig writes the rendered wg0.conf to disk, and -- when a Mikrotik
// integration is Enabled -- also pushes the same server/peer config to
// the RouterOS 7 device over SSH (see internal/library/mikrotik).
func (c *ServerController) ApplyConfig(w http.ResponseWriter, r *http.Request, params []string) {
	server, err := c.db.GetServer()
	if err != nil {
		core.InternalError(w, "Could not get the server configuration", err)
		return
	}
	clients, err := c.db.GetClients(false)
	if err != nil {
		core.InternalError(w, "Could not get the client configuration", err)
		return
	}
	users, err := c.db.GetUsers()
	if err != nil {
		core.InternalError(w, "Could not get the user configuration", err)
		return
	}
	settings, err := c.db.GetGlobalSettings()
	if err != nil {
		core.InternalError(w, "Could not get the global settings", err)
		return
	}

	if err := library.WriteWireGuardServerConfig(c.wgConfTemplate, server, clients, users, settings); err != nil {
		core.InternalError(w, "Could not apply the server configuration", err)
		return
	}

	mikrotikSettings, err := c.db.GetMikrotikSettings()
	if err != nil {
		core.InternalError(w, "Could not get the Mikrotik settings", err)
		return
	}
	if mikrotikSettings.Enabled {
		if err := mikrotik.ApplySync(mikrotikSettings, server, clients, settings); err != nil {
			core.InternalError(w, "Applied locally, but failed to sync to the Mikrotik device: "+err.Error(), err)
			return
		}
	}

	if err := library.UpdateHashes(c.db); err != nil {
		core.InternalError(w, "Could not update the configuration hashes", err)
		return
	}

	core.Success(w, "Server configuration applied successfully", nil)
}
