package model

import "time"

// WgInterface is one WireGuard network interface (wireguard1, wireguard2,
// ...). WireGuard has no structural client/server distinction at the
// interface level, only per-peer: a single interface can simultaneously
// accept inbound peers (server role) and dial out to other peers (client
// role) -- see Client.Endpoint, which switches an individual peer between
// those two roles.
type WgInterface struct {
	ID     string `json:"id"`
	Name   string `json:"name"`    // human label, e.g. "Office VPN"
	WgName string `json:"wg_name"` // RouterOS/kernel interface name, e.g. "wireguard1"

	KeyPair WgInterfaceKeypair `json:"key_pair"`
	Config  WgInterfaceConfig  `json:"config"`

	// Per-interface equivalents of what used to be the single global
	// setting, since each interface now has its own endpoint, DNS, MTU,
	// etc.
	EndpointAddress     string   `json:"endpoint_address"`
	DNSServers          []string `json:"dns_servers"`
	MTU                 int      `json:"mtu,string"`
	PersistentKeepalive int      `json:"persistent_keepalive,string"`
	FirewallMark        string   `json:"firewall_mark"`
	Table               string   `json:"table"`
	ConfigFilePath      string   `json:"config_file_path"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// WgInterfaceKeypair is this interface's own WireGuard key pair.
type WgInterfaceKeypair struct {
	PrivateKey string    `json:"private_key"`
	PublicKey  string    `json:"public_key"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// WgInterfaceConfig is the local [Interface] section of this interface's
// wg-quick config.
type WgInterfaceConfig struct {
	Addresses  []string  `json:"addresses"`
	ListenPort int       `json:"listen_port,string"`
	PostUp     string    `json:"post_up"`
	PreDown    string    `json:"pre_down"`
	PostDown   string    `json:"post_down"`
	UpdatedAt  time.Time `json:"updated_at"`
}
