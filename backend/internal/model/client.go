package model

import "time"

// Client is a WireGuard peer configuration, scoped to one WgInterface.
//
// Endpoint switches this peer between the two roles a WireGuard peer can
// take (see WgInterface's doc comment): left blank, the interface just
// waits for this peer to connect in (the common "allowed client" case,
// e.g. a phone running the WireGuard app). Set to "host:port", the
// interface instead dials out to that address -- this is the "Connect To"
// / site-to-site case, and PublicKey must then be the *remote* WireGuard
// server's own public key (not one generated for this record), since we
// don't control its private key.
type Client struct {
	ID              string    `json:"id"`
	InterfaceID     string    `json:"interface_id"`
	PrivateKey      string    `json:"private_key"`
	PublicKey       string    `json:"public_key"`
	PresharedKey    string    `json:"preshared_key"`
	Name            string    `json:"name"`
	TgUserid        string    `json:"telegram_userid"`
	Email           string    `json:"email"`
	SubnetRanges    []string  `json:"subnet_ranges,omitempty"`
	AllocatedIPs    []string  `json:"allocated_ips"`
	AllowedIPs      []string  `json:"allowed_ips"`
	ExtraAllowedIPs []string  `json:"extra_allowed_ips"`
	Endpoint        string    `json:"endpoint"`
	AdditionalNotes string    `json:"additional_notes"`
	UseServerDNS    bool      `json:"use_server_dns"`
	Enabled         bool      `json:"enabled"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// IsUpstream reports whether this client/peer record represents an
// outbound "Connect To" connection (this interface dials out to it) as
// opposed to an inbound allowed client (which waits to be connected to).
func (c Client) IsUpstream() bool {
	return c.Endpoint != ""
}

// ClientData bundles a Client with its rendered QR code image (data URI).
type ClientData struct {
	Client *Client `json:"client"`
	QRCode string  `json:"qr_code,omitempty"`
}

// QRCodeSettings controls what gets embedded into a generated QR code.
type QRCodeSettings struct {
	Enabled    bool
	IncludeDNS bool
	IncludeMTU bool
}

// ClientDefaults are the suggested defaults the frontend pre-fills when
// creating a new client.
type ClientDefaults struct {
	AllowedIps          []string `json:"allowed_ips"`
	ExtraAllowedIps     []string `json:"extra_allowed_ips"`
	UseServerDNS        bool     `json:"use_server_dns"`
	EnableAfterCreation bool     `json:"enable_after_creation"`
}
