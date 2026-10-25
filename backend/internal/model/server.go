package model

import "time"

// Server bundles the WireGuard server's interface settings and key pair.
type Server struct {
	KeyPair   *ServerKeypair   `json:"key_pair"`
	Interface *ServerInterface `json:"interface"`
}

// ServerKeypair is the WireGuard server's own key pair.
type ServerKeypair struct {
	PrivateKey string    `json:"private_key"`
	PublicKey  string    `json:"public_key"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// ServerInterface is the local [Interface] section of the server's wg0.conf.
type ServerInterface struct {
	Addresses  []string  `json:"addresses"`
	ListenPort int       `json:"listen_port,string"`
	UpdatedAt  time.Time `json:"updated_at"`
	PostUp     string    `json:"post_up"`
	PreDown    string    `json:"pre_down"`
	PostDown   string    `json:"post_down"`
}
