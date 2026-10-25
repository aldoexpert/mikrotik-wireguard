package model

import "time"

// Client is a WireGuard peer configuration.
type Client struct {
	ID              string    `json:"id"`
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
