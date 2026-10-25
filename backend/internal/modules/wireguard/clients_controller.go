package wireguard

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/xid"
	"github.com/skip2/go-qrcode"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/aldoexpert/mikrotik-wireguard/internal/config"
	"github.com/aldoexpert/mikrotik-wireguard/internal/core"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/emailer"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/store"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/telegram"
	"github.com/aldoexpert/mikrotik-wireguard/internal/model"
)

const (
	defaultEmailSubject = "Your WireGuard configuration"
	defaultEmailContent = `Hi,</br>
<p>In this email you can find your personal configuration for our WireGuard server.</p>

<p>Best</p>
`
)

var defaultQRCodeSettings = model.QRCodeSettings{Enabled: true, IncludeDNS: true, IncludeMTU: true}

type ClientsController struct {
	cfg    *config.App
	db     store.IStore
	mailer emailer.Emailer
}

func NewClientsController(cfg *config.App, db store.IStore, mailer emailer.Emailer) *ClientsController {
	return &ClientsController{cfg: cfg, db: db, mailer: mailer}
}

// Defaults returns the suggested defaults the frontend pre-fills when
// creating a new client.
func (c *ClientsController) Defaults(w http.ResponseWriter, r *http.Request, params []string) {
	core.Success(w, "", library.ClientDefaultsFromEnv())
}

// List returns every client, with QR code and resolved subnet ranges.
func (c *ClientsController) List(w http.ResponseWriter, r *http.Request, params []string) {
	clients, err := c.db.GetClients(true)
	if err != nil {
		core.InternalError(w, "Could not get the client list", err)
		return
	}
	for i := range clients {
		clients[i] = library.FillClientSubnetRange(clients[i])
	}
	core.SuccessList(w, "", clients)
}

// Get returns a single client by id.
func (c *ClientsController) Get(w http.ResponseWriter, r *http.Request, params []string) {
	if len(params) < 1 {
		core.BadRequest(w, "Client ID is required")
		return
	}
	clientID := params[0]
	if _, err := xid.FromString(clientID); err != nil {
		core.BadRequest(w, "Invalid client ID")
		return
	}

	clientData, err := c.db.GetClientByID(clientID, defaultQRCodeSettings)
	if err != nil {
		core.NotFound(w, "Client not found")
		return
	}
	core.Success(w, "", library.FillClientSubnetRange(clientData))
}

// Create adds a new client (WireGuard peer).
func (c *ClientsController) Create(w http.ResponseWriter, r *http.Request, params []string) {
	var client model.Client
	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		core.BadRequest(w, "Invalid client data")
		return
	}

	if err := library.ValidateClientName(client.Name); err != nil {
		core.BadRequest(w, err.Error())
		return
	}

	if client.TgUserid != "" {
		idNum, err := strconv.ParseInt(client.TgUserid, 10, 64)
		if err != nil || idNum == 0 {
			core.BadRequest(w, "Telegram userid must be a non-zero number")
			return
		}
	}

	server, err := c.db.GetServer()
	if err != nil {
		core.InternalError(w, "Could not get the server configuration", err)
		return
	}

	allocatedIPs, err := library.GetAllocatedIPs(c.db, "")
	if err != nil {
		core.InternalError(w, "Could not get the allocated IP list", err)
		return
	}
	if ok, verr := library.ValidateIPAllocation(server.Interface.Addresses, allocatedIPs, client.AllocatedIPs); !ok {
		core.BadRequest(w, verr.Error())
		return
	}

	if !library.ValidateAllowedIPs(client.AllowedIPs) {
		core.BadRequest(w, "Allowed IPs must be in CIDR format")
		return
	}
	if !library.ValidateExtraAllowedIPs(client.ExtraAllowedIPs) {
		core.BadRequest(w, "Extra Allowed IPs must be in CIDR format")
		return
	}

	client.ID = xid.New().String()

	if client.PublicKey == "" {
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			core.InternalError(w, "Could not generate a WireGuard key pair", err)
			return
		}
		client.PrivateKey = key.String()
		client.PublicKey = key.PublicKey().String()
	} else {
		if _, err := wgtypes.ParseKey(client.PublicKey); err != nil {
			core.InternalError(w, "Could not verify the WireGuard public key", err)
			return
		}
		if dup, err := c.hasDuplicatePublicKey(client.PublicKey, ""); err != nil {
			core.InternalError(w, "Could not check for a duplicate public key", err)
			return
		} else if dup {
			core.InternalError(w, "Public key already in use", nil)
			return
		}
	}

	switch client.PresharedKey {
	case "":
		presharedKey, err := wgtypes.GenerateKey()
		if err != nil {
			core.InternalError(w, "Could not generate a WireGuard preshared key", err)
			return
		}
		client.PresharedKey = presharedKey.String()
	case "-":
		client.PresharedKey = ""
	default:
		if _, err := wgtypes.ParseKey(client.PresharedKey); err != nil {
			core.InternalError(w, "Could not verify the WireGuard preshared key", err)
			return
		}
	}

	client.CreatedAt = time.Now().UTC()
	client.UpdatedAt = client.CreatedAt

	if err := c.db.SaveClient(client); err != nil {
		core.InternalError(w, err.Error(), err)
		return
	}

	core.Success(w, "Client created successfully", client)
}

func (c *ClientsController) hasDuplicatePublicKey(publicKey, ignoreClientID string) (bool, error) {
	clients, err := c.db.GetClients(false)
	if err != nil {
		return false, err
	}
	for _, other := range clients {
		if other.Client.ID != ignoreClientID && other.Client.PublicKey == publicKey {
			return true, nil
		}
	}
	return false, nil
}

// Update edits an existing client.
func (c *ClientsController) Update(w http.ResponseWriter, r *http.Request, params []string) {
	var updated model.Client
	if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
		core.BadRequest(w, "Invalid client data")
		return
	}

	if _, err := xid.FromString(updated.ID); err != nil {
		core.BadRequest(w, "Invalid client ID")
		return
	}

	existing, err := c.db.GetClientByID(updated.ID, model.QRCodeSettings{Enabled: false})
	if err != nil {
		core.NotFound(w, "Client not found")
		return
	}

	if err := library.ValidateClientName(updated.Name); err != nil {
		core.BadRequest(w, err.Error())
		return
	}

	if updated.TgUserid != "" {
		idNum, err := strconv.ParseInt(updated.TgUserid, 10, 64)
		if err != nil || idNum == 0 {
			core.BadRequest(w, "Telegram userid must be a non-zero number")
			return
		}
	}

	server, err := c.db.GetServer()
	if err != nil {
		core.BadRequest(w, fmt.Sprintf("Could not get the server configuration: %s", err))
		return
	}

	client := *existing.Client

	allocatedIPs, err := library.GetAllocatedIPs(c.db, client.ID)
	if err != nil {
		core.InternalError(w, "Could not get the allocated IP list", err)
		return
	}
	if ok, verr := library.ValidateIPAllocation(server.Interface.Addresses, allocatedIPs, updated.AllocatedIPs); !ok {
		core.BadRequest(w, verr.Error())
		return
	}

	if !library.ValidateAllowedIPs(updated.AllowedIPs) {
		core.BadRequest(w, "Allowed IPs must be in CIDR format")
		return
	}
	if !library.ValidateExtraAllowedIPs(updated.ExtraAllowedIPs) {
		core.BadRequest(w, "Extra Allowed IPs must be in CIDR format")
		return
	}

	if client.PublicKey != updated.PublicKey && updated.PublicKey != "" {
		if _, err := wgtypes.ParseKey(updated.PublicKey); err != nil {
			core.InternalError(w, "Could not verify the WireGuard public key", err)
			return
		}
		if dup, err := c.hasDuplicatePublicKey(updated.PublicKey, client.ID); err != nil {
			core.InternalError(w, "Could not check for a duplicate public key", err)
			return
		} else if dup {
			core.InternalError(w, "Public key already in use", nil)
			return
		}
		// Replacing the public key invalidates any locally stored private
		// key: it no longer matches, and the QR code requires it.
		client.PrivateKey = ""
	}

	if client.PresharedKey != updated.PresharedKey && updated.PresharedKey != "" {
		if _, err := wgtypes.ParseKey(updated.PresharedKey); err != nil {
			core.InternalError(w, "Could not verify the WireGuard preshared key", err)
			return
		}
	}

	client.Name = updated.Name
	client.Email = updated.Email
	client.TgUserid = updated.TgUserid
	client.Enabled = updated.Enabled
	client.UseServerDNS = updated.UseServerDNS
	client.AllocatedIPs = updated.AllocatedIPs
	client.AllowedIPs = updated.AllowedIPs
	client.ExtraAllowedIPs = updated.ExtraAllowedIPs
	client.Endpoint = updated.Endpoint
	client.PublicKey = updated.PublicKey
	client.PresharedKey = updated.PresharedKey
	client.UpdatedAt = time.Now().UTC()
	client.AdditionalNotes = strings.ReplaceAll(strings.Trim(updated.AdditionalNotes, "\r\n"), "\r\n", "\n")

	if err := c.db.SaveClient(client); err != nil {
		core.InternalError(w, err.Error(), err)
		return
	}

	core.Success(w, "Client updated successfully", nil)
}

type setStatusPayload struct {
	ID     string `json:"id"`
	Status bool   `json:"status"`
}

// SetStatus enables/disables a client without touching its other fields.
func (c *ClientsController) SetStatus(w http.ResponseWriter, r *http.Request, params []string) {
	var payload setStatusPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		core.BadRequest(w, "Invalid data")
		return
	}
	if _, err := xid.FromString(payload.ID); err != nil {
		core.BadRequest(w, "Invalid client ID")
		return
	}

	clientData, err := c.db.GetClientByID(payload.ID, model.QRCodeSettings{Enabled: false})
	if err != nil {
		core.NotFound(w, err.Error())
		return
	}

	client := *clientData.Client
	client.Enabled = payload.Status
	if err := c.db.SaveClient(client); err != nil {
		core.InternalError(w, err.Error(), err)
		return
	}

	core.Success(w, "Client status updated successfully", nil)
}

// Delete removes a client.
func (c *ClientsController) Delete(w http.ResponseWriter, r *http.Request, params []string) {
	var payload struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		core.BadRequest(w, "Invalid data")
		return
	}
	if _, err := xid.FromString(payload.ID); err != nil {
		core.BadRequest(w, "Invalid client ID")
		return
	}

	if err := c.db.DeleteClient(payload.ID); err != nil {
		core.InternalError(w, "Could not delete the client from the database", err)
		return
	}

	core.Success(w, "Client deleted successfully", nil)
}

// Download streams the client's .conf file.
func (c *ClientsController) Download(w http.ResponseWriter, r *http.Request, params []string) {
	if len(params) < 1 {
		core.BadRequest(w, "Client ID is required")
		return
	}
	clientID := params[0]
	if _, err := xid.FromString(clientID); err != nil {
		core.BadRequest(w, "Invalid client ID")
		return
	}

	clientData, err := c.db.GetClientByID(clientID, model.QRCodeSettings{Enabled: false})
	if err != nil {
		core.NotFound(w, "Client not found")
		return
	}

	server, err := c.db.GetServer()
	if err != nil {
		core.InternalError(w, err.Error(), err)
		return
	}
	globalSettings, err := c.db.GetGlobalSettings()
	if err != nil {
		core.InternalError(w, err.Error(), err)
		return
	}

	conf := library.BuildClientConfig(*clientData.Client, server, globalSettings)

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.conf", clientData.Client.Name))
	w.Header().Set("Content-Type", "text/conf")
	w.Write([]byte(conf))
}

type emailPayload struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// Email sends the client's configuration (file + QR code) by email.
func (c *ClientsController) Email(w http.ResponseWriter, r *http.Request, params []string) {
	if c.mailer == nil {
		core.InternalError(w, "Email is not configured on this server", nil)
		return
	}

	var payload emailPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		core.BadRequest(w, "Invalid data")
		return
	}
	if _, err := xid.FromString(payload.ID); err != nil {
		core.BadRequest(w, "Invalid client ID")
		return
	}

	clientData, err := c.db.GetClientByID(payload.ID, defaultQRCodeSettings)
	if err != nil {
		core.NotFound(w, "Client not found")
		return
	}

	server, _ := c.db.GetServer()
	globalSettings, _ := c.db.GetGlobalSettings()
	conf := library.BuildClientConfig(*clientData.Client, server, globalSettings)

	cfgAttachment := emailer.Attachment{Name: "wg0.conf", Data: []byte(conf)}
	attachments := []emailer.Attachment{cfgAttachment}
	if clientData.Client.PrivateKey != "" {
		qrData, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(clientData.QRCode, "data:image/png;base64,"))
		if err != nil {
			core.InternalError(w, "decoding: "+err.Error(), err)
			return
		}
		attachments = append(attachments, emailer.Attachment{Name: "wg.png", Data: qrData})
	}

	if err := c.mailer.Send(clientData.Client.Name, payload.Email, defaultEmailSubject, defaultEmailContent, attachments); err != nil {
		core.InternalError(w, err.Error(), err)
		return
	}

	core.Success(w, "Email sent successfully", nil)
}

type telegramPayload struct {
	ID     string `json:"id"`
	Userid string `json:"userid"`
}

// Telegram sends the client's configuration via the Telegram bot.
func (c *ClientsController) Telegram(w http.ResponseWriter, r *http.Request, params []string) {
	var payload telegramPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		core.BadRequest(w, "Invalid data")
		return
	}

	clientData, err := c.db.GetClientByID(payload.ID, model.QRCodeSettings{Enabled: false})
	if err != nil {
		core.NotFound(w, "Client not found")
		return
	}

	server, _ := c.db.GetServer()
	globalSettings, _ := c.db.GetGlobalSettings()
	conf := library.BuildClientConfig(*clientData.Client, server, globalSettings)
	confData := []byte(conf)

	var qrData []byte
	if clientData.Client.PrivateKey != "" {
		qrData, err = qrcode.Encode(conf, qrcode.Medium, 512)
		if err != nil {
			core.InternalError(w, "qr gen: "+err.Error(), err)
			return
		}
	}

	userid, err := strconv.ParseInt(clientData.Client.TgUserid, 10, 64)
	if err != nil {
		core.InternalError(w, "userid: "+err.Error(), err)
		return
	}

	if err := telegram.SendConfig(userid, clientData.Client.Name, confData, qrData, false); err != nil {
		core.InternalError(w, err.Error(), err)
		return
	}

	core.Success(w, "Telegram message sent successfully", nil)
}

// SuggestIPs suggests the next free IP address for a new client, optionally
// restricted to the named subnet range ("sr" query param).
func (c *ClientsController) SuggestIPs(w http.ResponseWriter, r *http.Request, params []string) {
	server, err := c.db.GetServer()
	if err != nil {
		core.BadRequest(w, err.Error())
		return
	}

	allocatedIPs, err := library.GetAllocatedIPs(c.db, "")
	if err != nil {
		core.InternalError(w, "Could not get the allocated IP list", err)
		return
	}

	sr := r.URL.Query().Get("sr")
	var searchCIDRList []string
	if library.SubnetRanges[sr] != nil {
		for _, cidr := range library.SubnetRanges[sr] {
			searchCIDRList = append(searchCIDRList, cidr.String())
		}
	} else {
		searchCIDRList = append(searchCIDRList, server.Interface.Addresses...)
	}

	found := false
	ipSet := make(map[string]struct{})
	for _, cidr := range searchCIDRList {
		ip, err := library.GetAvailableIP(cidr, allocatedIPs, server.Interface.Addresses)
		if err != nil {
			continue
		}
		found = true
		if strings.Contains(ip, ":") {
			ipSet[fmt.Sprintf("%s/128", ip)] = struct{}{}
		} else {
			ipSet[fmt.Sprintf("%s/32", ip)] = struct{}{}
		}
	}

	if !found {
		core.InternalError(w, "Could not suggest an IP: no address is available. Try a different subnet or free up some IPs.", nil)
		return
	}

	suggested := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		suggested = append(suggested, ip)
	}

	core.SuccessList(w, "", suggested)
}
