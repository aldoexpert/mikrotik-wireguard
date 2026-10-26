package wireguard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/xid"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/aldoexpert/mikrotik-wireguard/internal/core"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/mikrotik"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/store"
	"github.com/aldoexpert/mikrotik-wireguard/internal/model"
)

type InterfacesController struct {
	db             store.IStore
	wgConfTemplate string
}

func NewInterfacesController(db store.IStore, wgConfTemplate string) *InterfacesController {
	return &InterfacesController{db: db, wgConfTemplate: wgConfTemplate}
}

// List returns every WireGuard interface.
func (c *InterfacesController) List(w http.ResponseWriter, r *http.Request, params []string) {
	ifaces, err := c.db.GetInterfaces()
	if err != nil {
		core.InternalError(w, "Could not get the interface list", err)
		return
	}
	core.SuccessList(w, "", ifaces)
}

// Get returns one interface by id.
func (c *InterfacesController) Get(w http.ResponseWriter, r *http.Request, params []string) {
	if len(params) < 1 {
		core.BadRequest(w, "Interface ID is required")
		return
	}
	iface, err := c.db.GetInterfaceByID(params[0])
	if err != nil {
		core.NotFound(w, "Interface not found")
		return
	}
	core.Success(w, "", iface)
}

type interfaceRequest struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	WgName              string   `json:"wg_name"`
	Addresses           []string `json:"addresses"`
	ListenPort          int      `json:"listen_port,string"`
	PostUp              string   `json:"post_up"`
	PreDown             string   `json:"pre_down"`
	PostDown            string   `json:"post_down"`
	EndpointAddress     string   `json:"endpoint_address"`
	DNSServers          []string `json:"dns_servers"`
	MTU                 int      `json:"mtu,string"`
	PersistentKeepalive int      `json:"persistent_keepalive,string"`
	FirewallMark        string   `json:"firewall_mark"`
	Table               string   `json:"table"`
	ConfigFilePath      string   `json:"config_file_path"`
}

func (req interfaceRequest) validate() error {
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}
	if req.WgName == "" {
		return fmt.Errorf("interface name (wg_name) is required")
	}
	if !library.ValidateServerAddresses(req.Addresses) {
		return fmt.Errorf("interface IP address must be in CIDR format")
	}
	if !library.ValidateIPAddressList(req.DNSServers) {
		return fmt.Errorf("invalid DNS server address")
	}
	if req.ConfigFilePath == "" {
		return fmt.Errorf("config file path is required")
	}
	return nil
}

// Create adds a new WireGuard interface, with a freshly generated key pair.
func (c *InterfacesController) Create(w http.ResponseWriter, r *http.Request, params []string) {
	var req interfaceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Invalid data")
		return
	}
	if err := req.validate(); err != nil {
		core.BadRequest(w, err.Error())
		return
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		core.InternalError(w, "Could not generate a WireGuard key pair", err)
		return
	}

	now := time.Now().UTC()
	iface := model.WgInterface{
		ID:     xid.New().String(),
		Name:   req.Name,
		WgName: req.WgName,
		KeyPair: model.WgInterfaceKeypair{
			PrivateKey: key.String(),
			PublicKey:  key.PublicKey().String(),
			UpdatedAt:  now,
		},
		Config: model.WgInterfaceConfig{
			Addresses:  req.Addresses,
			ListenPort: req.ListenPort,
			PostUp:     req.PostUp,
			PreDown:    req.PreDown,
			PostDown:   req.PostDown,
			UpdatedAt:  now,
		},
		EndpointAddress:     req.EndpointAddress,
		DNSServers:          req.DNSServers,
		MTU:                 req.MTU,
		PersistentKeepalive: req.PersistentKeepalive,
		FirewallMark:        req.FirewallMark,
		Table:               req.Table,
		ConfigFilePath:      req.ConfigFilePath,
		CreatedAt:           now,
		UpdatedAt:           now,
	}

	if err := c.db.SaveInterface(iface); err != nil {
		core.InternalError(w, "Could not save the interface", err)
		return
	}

	core.Success(w, "Interface created successfully", iface)
}

// Update edits an existing interface's configuration (not its key pair --
// see UpdateKeyPair).
func (c *InterfacesController) Update(w http.ResponseWriter, r *http.Request, params []string) {
	var req interfaceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		core.BadRequest(w, "Invalid data")
		return
	}
	if req.ID == "" {
		core.BadRequest(w, "Interface ID is required")
		return
	}
	if err := req.validate(); err != nil {
		core.BadRequest(w, err.Error())
		return
	}

	iface, err := c.db.GetInterfaceByID(req.ID)
	if err != nil {
		core.NotFound(w, "Interface not found")
		return
	}

	now := time.Now().UTC()
	iface.Name = req.Name
	iface.WgName = req.WgName
	iface.Config.Addresses = req.Addresses
	iface.Config.ListenPort = req.ListenPort
	iface.Config.PostUp = req.PostUp
	iface.Config.PreDown = req.PreDown
	iface.Config.PostDown = req.PostDown
	iface.Config.UpdatedAt = now
	iface.EndpointAddress = req.EndpointAddress
	iface.DNSServers = req.DNSServers
	iface.MTU = req.MTU
	iface.PersistentKeepalive = req.PersistentKeepalive
	iface.FirewallMark = req.FirewallMark
	iface.Table = req.Table
	iface.ConfigFilePath = req.ConfigFilePath
	iface.UpdatedAt = now

	if err := c.db.SaveInterface(iface); err != nil {
		core.InternalError(w, "Could not save the interface", err)
		return
	}

	core.Success(w, "Interface updated successfully", iface)
}

// UpdateKeyPair generates and stores a fresh key pair for one interface.
func (c *InterfacesController) UpdateKeyPair(w http.ResponseWriter, r *http.Request, params []string) {
	var payload struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		core.BadRequest(w, "Invalid data")
		return
	}

	iface, err := c.db.GetInterfaceByID(payload.ID)
	if err != nil {
		core.NotFound(w, "Interface not found")
		return
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		core.InternalError(w, "Could not generate a WireGuard key pair", err)
		return
	}

	iface.KeyPair = model.WgInterfaceKeypair{
		PrivateKey: key.String(),
		PublicKey:  key.PublicKey().String(),
		UpdatedAt:  time.Now().UTC(),
	}
	iface.UpdatedAt = time.Now().UTC()

	if err := c.db.SaveInterface(iface); err != nil {
		core.InternalError(w, "Could not save the interface", err)
		return
	}

	core.Success(w, "Interface key pair updated successfully", iface)
}

// Delete removes an interface. Refuses if any client is still assigned to
// it, so deleting an interface never silently orphans its clients.
func (c *InterfacesController) Delete(w http.ResponseWriter, r *http.Request, params []string) {
	var payload struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		core.BadRequest(w, "Invalid data")
		return
	}

	clients, err := c.db.GetClients(false)
	if err != nil {
		core.InternalError(w, "Could not get the client list", err)
		return
	}
	for _, cd := range clients {
		if cd.Client != nil && cd.Client.InterfaceID == payload.ID {
			core.BadRequest(w, "This interface still has clients assigned to it. Move or delete them first.")
			return
		}
	}

	if err := c.db.DeleteInterface(payload.ID); err != nil {
		core.InternalError(w, "Could not delete the interface", err)
		return
	}

	core.Success(w, "Interface deleted successfully", nil)
}

// applyOne writes iface's local wg-quick config and, when the Mikrotik
// integration is Enabled, pushes the same config to the RouterOS device.
func (c *InterfacesController) applyOne(iface model.WgInterface, mikrotikSettings model.MikrotikSettings, users []model.User) error {
	clients, err := c.db.GetClients(false)
	if err != nil {
		return err
	}
	var scoped []model.ClientData
	for _, cd := range clients {
		if cd.Client != nil && cd.Client.InterfaceID == iface.ID {
			scoped = append(scoped, cd)
		}
	}

	if err := library.WriteWireGuardServerConfig(c.wgConfTemplate, iface, scoped, users); err != nil {
		return err
	}

	if mikrotikSettings.Enabled {
		if err := mikrotik.ApplySync(mikrotikSettings, iface, scoped); err != nil {
			return fmt.Errorf("applied locally, but failed to sync %s to the Mikrotik device: %w", iface.WgName, err)
		}
	}
	return nil
}

// ApplyConfig applies a single interface (id in the request body).
func (c *InterfacesController) ApplyConfig(w http.ResponseWriter, r *http.Request, params []string) {
	var payload struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		core.BadRequest(w, "Invalid data")
		return
	}

	iface, err := c.db.GetInterfaceByID(payload.ID)
	if err != nil {
		core.NotFound(w, "Interface not found")
		return
	}
	users, err := c.db.GetUsers()
	if err != nil {
		core.InternalError(w, "Could not get the user configuration", err)
		return
	}
	mikrotikSettings, err := c.db.GetMikrotikSettings()
	if err != nil {
		core.InternalError(w, "Could not get the Mikrotik settings", err)
		return
	}

	if err := c.applyOne(iface, mikrotikSettings, users); err != nil {
		core.InternalError(w, "Could not apply the interface configuration: "+err.Error(), err)
		return
	}

	if err := library.UpdateHashes(c.db); err != nil {
		core.InternalError(w, "Could not update the configuration hashes", err)
		return
	}

	core.Success(w, "Interface configuration applied successfully", nil)
}

// ApplyAll applies every interface in one call.
func (c *InterfacesController) ApplyAll(w http.ResponseWriter, r *http.Request, params []string) {
	ifaces, err := c.db.GetInterfaces()
	if err != nil {
		core.InternalError(w, "Could not get the interface list", err)
		return
	}
	users, err := c.db.GetUsers()
	if err != nil {
		core.InternalError(w, "Could not get the user configuration", err)
		return
	}
	mikrotikSettings, err := c.db.GetMikrotikSettings()
	if err != nil {
		core.InternalError(w, "Could not get the Mikrotik settings", err)
		return
	}

	for _, iface := range ifaces {
		if err := c.applyOne(iface, mikrotikSettings, users); err != nil {
			core.InternalError(w, fmt.Sprintf("Could not apply interface %q: %s", iface.Name, err.Error()), err)
			return
		}
	}

	if err := library.UpdateHashes(c.db); err != nil {
		core.InternalError(w, "Could not update the configuration hashes", err)
		return
	}

	core.Success(w, "All interfaces applied successfully", nil)
}
