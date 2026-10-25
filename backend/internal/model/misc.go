package model

// Interface is a local network interface's name and IP address.
type Interface struct {
	Name      string `json:"name"`
	IPAddress string `json:"ip_address"`
}

// ClientServerHashes is used to detect uncommitted client/server config
// changes that still need to be "applied".
type ClientServerHashes struct {
	Client string `json:"client"`
	Server string `json:"server"`
}
