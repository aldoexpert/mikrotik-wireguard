package model

import (
	"errors"
	"net"
	"strings"
	"time"
)

// WakeOnLanHost is a saved LAN host that can be woken up via a magic packet.
type WakeOnLanHost struct {
	MacAddress string     `json:"mac_address"`
	Name       string     `json:"name"`
	LatestUsed *time.Time `json:"latest_used"`
}

// ResolveResourceName normalizes the MAC address into the on-disk record
// name (uppercase, dash separated) and validates its format.
func (host WakeOnLanHost) ResolveResourceName() (string, error) {
	resourceName := strings.Trim(host.MacAddress, " \t\r\n\000")
	if len(resourceName) == 0 {
		return "", errors.New("mac address is empty")
	}
	resourceName = strings.ToUpper(resourceName)
	resourceName = strings.ReplaceAll(resourceName, ":", "-")

	if _, err := net.ParseMAC(resourceName); err != nil {
		return "", errors.New("invalid mac address")
	}

	return resourceName, nil
}

const WakeOnLanHostCollectionName = "wake_on_lan_hosts"
