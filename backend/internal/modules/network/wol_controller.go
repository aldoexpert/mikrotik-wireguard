package network

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/sabhiram/go-wol/wol"

	"github.com/aldoexpert/mikrotik-wireguard/internal/core"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/store"
	"github.com/aldoexpert/mikrotik-wireguard/internal/model"
)

type WolController struct {
	db store.IStore
}

func NewWolController(db store.IStore) *WolController {
	return &WolController{db: db}
}

// List returns every saved Wake-on-LAN host.
func (c *WolController) List(w http.ResponseWriter, r *http.Request, params []string) {
	hosts, err := c.db.GetWakeOnLanHosts()
	if err != nil {
		core.InternalError(w, "Could not get the host list", err)
		return
	}
	core.SuccessList(w, "", hosts)
}

type savePayload struct {
	Name          string `json:"name"`
	MacAddress    string `json:"mac_address"`
	OldMacAddress string `json:"old_mac_address"`
}

// Save creates or renames/updates a Wake-on-LAN host entry.
func (c *WolController) Save(w http.ResponseWriter, r *http.Request, params []string) {
	var payload savePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		core.BadRequest(w, "Invalid data")
		return
	}

	host := model.WakeOnLanHost{MacAddress: payload.MacAddress, Name: payload.Name}

	if payload.OldMacAddress != "" {
		if payload.OldMacAddress != payload.MacAddress {
			oldHost, err := c.db.GetWakeOnLanHost(payload.OldMacAddress)
			if err != nil {
				core.InternalError(w, "Could not update the host: "+err.Error(), err)
				return
			}
			if existing, _ := c.db.GetWakeOnLanHost(payload.MacAddress); existing != nil {
				core.InternalError(w, "This MAC address already exists", nil)
				return
			}
			if err := c.db.DeleteWakeOnHostLanHost(payload.OldMacAddress); err != nil {
				core.InternalError(w, "Could not update the host: "+err.Error(), err)
				return
			}
			host.LatestUsed = oldHost.LatestUsed
		}
	} else {
		if existing, _ := c.db.GetWakeOnLanHost(payload.MacAddress); existing != nil {
			core.InternalError(w, "This MAC address already exists", nil)
			return
		}
	}

	if err := c.db.SaveWakeOnLanHost(host); err != nil {
		core.InternalError(w, "Could not save the host: "+err.Error(), err)
		return
	}

	core.Success(w, "Host saved successfully", host)
}

type macPayload struct {
	MacAddress string `json:"mac_address"`
}

// Delete removes a saved Wake-on-LAN host.
func (c *WolController) Delete(w http.ResponseWriter, r *http.Request, params []string) {
	var payload macPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		core.BadRequest(w, "Invalid data")
		return
	}

	host, err := c.db.GetWakeOnLanHost(payload.MacAddress)
	if err != nil {
		core.InternalError(w, "Host not found: "+payload.MacAddress, err)
		return
	}
	if err := c.db.DeleteWakeOnHost(*host); err != nil {
		core.InternalError(w, "Could not delete the host: "+payload.MacAddress, err)
		return
	}

	core.Success(w, "Host deleted successfully", nil)
}

// Wake sends a magic packet to the host and records when it was last woken.
func (c *WolController) Wake(w http.ResponseWriter, r *http.Request, params []string) {
	var payload macPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		core.BadRequest(w, "Invalid data")
		return
	}

	host, err := c.db.GetWakeOnLanHost(payload.MacAddress)
	if err != nil {
		core.InternalError(w, "Host not found: "+payload.MacAddress, err)
		return
	}

	now := time.Now().UTC()
	host.LatestUsed = &now
	if err := c.db.SaveWakeOnLanHost(*host); err != nil {
		core.InternalError(w, "Could not update the last-used timestamp: "+payload.MacAddress, err)
		return
	}

	magicPacket, err := wol.New(payload.MacAddress)
	if err != nil {
		core.InternalError(w, "Could not create the magic packet: "+payload.MacAddress, err)
		return
	}
	packetBytes, err := magicPacket.Marshal()
	if err != nil {
		core.InternalError(w, "Could not create the magic packet byte stream: "+payload.MacAddress, err)
		return
	}

	udpAddr, err := net.ResolveUDPAddr("udp", "255.255.255.255:0")
	if err != nil {
		core.InternalError(w, "Could not resolve the UDP address: "+payload.MacAddress, err)
		return
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		core.InternalError(w, "Could not send the magic packet: "+payload.MacAddress, err)
		return
	}
	defer conn.Close()

	n, err := conn.Write(packetBytes)
	if err != nil {
		core.InternalError(w, "Failed to send over the network: "+payload.MacAddress, err)
		return
	}
	if n != 102 {
		core.InternalError(w, "The magic packet sent did not match the expected size (should be 102 bytes)", nil)
		return
	}

	core.Success(w, "Magic packet sent successfully", host.LatestUsed)
}
