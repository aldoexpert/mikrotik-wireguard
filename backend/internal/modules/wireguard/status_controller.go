package wireguard

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"

	"github.com/aldoexpert/mikrotik-wireguard/internal/core"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/mikrotik"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/store"
	"github.com/aldoexpert/mikrotik-wireguard/internal/middleware"
	"github.com/aldoexpert/mikrotik-wireguard/internal/model"
)

type StatusController struct {
	db store.IStore
}

func NewStatusController(db store.IStore) *StatusController {
	return &StatusController{db: db}
}

type peerStatus struct {
	Name              string    `json:"name"`
	Email             string    `json:"email"`
	PublicKey         string    `json:"public_key"`
	ReceivedBytes     int64     `json:"received_bytes"`
	TransmitBytes     int64     `json:"transmit_bytes"`
	LastHandshakeTime time.Time `json:"last_handshake_time"`
	LastHandshakeSecs float64   `json:"last_handshake_secs_ago"`
	Connected         bool      `json:"connected"`
	AllocatedIP       string    `json:"allocated_ip"`
	Endpoint          string    `json:"endpoint,omitempty"`
}

type deviceStatus struct {
	Name  string       `json:"name"`
	Peers []peerStatus `json:"peers"`
}

// Get returns the WireGuard device(s) and their peers' live handshake
// state -- from the Mikrotik device over SSH when that integration is
// Enabled, otherwise from the local kernel/userspace device via wgctrl.
func (c *StatusController) Get(w http.ResponseWriter, r *http.Request, params []string) {
	clients, err := c.db.GetClients(false)
	if err != nil {
		core.InternalError(w, "Could not get the client list", err)
		return
	}
	byPublicKey := make(map[string]*clientLookup, len(clients))
	for i := range clients {
		if clients[i].Client != nil {
			byPublicKey[clients[i].Client.PublicKey] = &clientLookup{Name: clients[i].Client.Name, Email: clients[i].Client.Email}
		}
	}

	mikrotikSettings, err := c.db.GetMikrotikSettings()
	if err != nil {
		core.InternalError(w, "Could not get the Mikrotik settings", err)
		return
	}

	isAdmin := middleware.IsAdmin(r)
	var result []deviceStatus
	if mikrotikSettings.Enabled {
		result, err = c.getFromMikrotik(mikrotikSettings, byPublicKey, isAdmin)
	} else {
		result, err = c.getFromLocal(byPublicKey, isAdmin)
	}
	if err != nil {
		core.InternalError(w, "Could not get the WireGuard status: "+err.Error(), err)
		return
	}

	core.SuccessList(w, "", result)
}

func (c *StatusController) getFromLocal(byPublicKey map[string]*clientLookup, isAdmin bool) ([]deviceStatus, error) {
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer wgClient.Close()

	devices, err := wgClient.Devices()
	if err != nil {
		return nil, err
	}

	result := make([]deviceStatus, 0, len(devices))
	for _, d := range devices {
		dev := deviceStatus{Name: d.Name}
		for _, p := range d.Peers {
			var allocatedIPs string
			for _, ip := range p.AllowedIPs {
				if allocatedIPs != "" {
					allocatedIPs += ", "
				}
				allocatedIPs += ip.String()
			}

			ps := peerStatus{
				PublicKey:         p.PublicKey.String(),
				ReceivedBytes:     p.ReceiveBytes,
				TransmitBytes:     p.TransmitBytes,
				LastHandshakeTime: p.LastHandshakeTime,
				LastHandshakeSecs: time.Since(p.LastHandshakeTime).Seconds(),
				AllocatedIP:       allocatedIPs,
			}
			ps.Connected = time.Since(p.LastHandshakeTime).Minutes() < 3

			if isAdmin {
				ps.Endpoint = p.Endpoint.String()
			}
			if cl, ok := byPublicKey[ps.PublicKey]; ok {
				ps.Name = cl.Name
				ps.Email = cl.Email
			}
			dev.Peers = append(dev.Peers, ps)
		}
		sortPeers(dev.Peers)
		result = append(result, dev)
	}
	return result, nil
}

func (c *StatusController) getFromMikrotik(settings model.MikrotikSettings, byPublicKey map[string]*clientLookup, isAdmin bool) ([]deviceStatus, error) {
	ifaces, err := c.db.GetInterfaces()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	result := make([]deviceStatus, 0, len(ifaces))
	for _, iface := range ifaces {
		peers, err := mikrotik.GetPeerStatuses(settings, iface.WgName)
		if err != nil {
			return nil, err
		}

		dev := deviceStatus{Name: iface.WgName}
		for _, p := range peers {
			ps := peerStatus{
				PublicKey:     p.PublicKey,
				ReceivedBytes: p.RxBytes,
				TransmitBytes: p.TxBytes,
				AllocatedIP:   strings.ReplaceAll(p.AllowedAddress, ",", ", "),
			}
			if d, ok := mikrotik.ParseDuration(p.LastHandshake); ok {
				ps.LastHandshakeTime = now.Add(-d)
				ps.LastHandshakeSecs = d.Seconds()
				ps.Connected = d.Minutes() < 3
			}
			if isAdmin {
				ps.Endpoint = p.EndpointAddress
			}
			if cl, ok := byPublicKey[ps.PublicKey]; ok {
				ps.Name = cl.Name
				ps.Email = cl.Email
			}
			dev.Peers = append(dev.Peers, ps)
		}
		sortPeers(dev.Peers)
		result = append(result, dev)
	}
	return result, nil
}

func sortPeers(peers []peerStatus) {
	sort.SliceStable(peers, func(i, j int) bool { return peers[i].Name < peers[j].Name })
	sort.SliceStable(peers, func(i, j int) bool { return boolToInt(peers[i].Connected) > boolToInt(peers[j].Connected) })
}

type clientLookup struct {
	Name  string
	Email string
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
