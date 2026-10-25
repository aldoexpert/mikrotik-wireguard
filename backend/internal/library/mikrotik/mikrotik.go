// Package mikrotik pushes this app's WireGuard server + client (peer)
// configuration to a Mikrotik RouterOS 7 device over SSH, replacing the
// local wg0.conf apply step when a MikrotikSettings record is Enabled.
//
// Auth is always by SSH private key (ssh.PublicKeys), never password --
// the key is generated once by the operator and installed on a dedicated,
// least-privilege RouterOS user (see README.md "Mikrotik integration").
//
// Idempotency: every peer this app manages is tagged with a comment of
// the form "mtwg:<client-id>". Re-applying finds peers by that comment
// (via RouterOS' own `find`), so this never needs to track RouterOS'
// internal ".id" values, and it never touches a peer it didn't create
// (any peer whose comment doesn't start with "mtwg:" is left alone).
package mikrotik

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aldoexpert/mikrotik-wireguard/internal/model"
)

const defaultInterfaceName = "wireguard1"

// Dial opens an SSH connection to the RouterOS device.
func Dial(settings model.MikrotikSettings) (*ssh.Client, error) {
	if settings.Host == "" {
		return nil, fmt.Errorf("no Mikrotik host configured")
	}
	if settings.PrivateKeyPEM == "" {
		return nil, fmt.Errorf("no SSH private key configured")
	}

	signer, err := ssh.ParsePrivateKey([]byte(settings.PrivateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("invalid SSH private key: %w", err)
	}

	port := settings.Port
	if port == 0 {
		port = 22
	}

	cfg := &ssh.ClientConfig{
		User:    settings.Username,
		Auth:    []ssh.AuthMethod{ssh.PublicKeys(signer)},
		Timeout: 10 * time.Second,
		// RouterOS devices here are reached over an operator-controlled
		// network path (not the public CA system); pinning the host key
		// fingerprint instead of this is a worthwhile future hardening
		// step, tracked in README.md.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	addr := fmt.Sprintf("%s:%d", settings.Host, port)
	return ssh.Dial("tcp", addr, cfg)
}

// run executes a RouterOS script (one or more statements, newline
// separated) in a single SSH session and returns its combined stdout.
func run(client *ssh.Client, script string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	if err := session.Run(script); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("%s", msg)
	}
	return stdout.String(), nil
}

// TestConnection verifies the stored host/credentials actually reach a
// RouterOS device, returning its configured system identity name.
func TestConnection(settings model.MikrotikSettings) (string, error) {
	client, err := Dial(settings)
	if err != nil {
		return "", err
	}
	defer client.Close()

	out, err := run(client, "/system identity print")
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(out)
	name = strings.TrimPrefix(name, "name:")
	return strings.TrimSpace(name), nil
}

// PeerStatus is one RouterOS WireGuard peer's live state, as shown by
// `/interface wireguard peers print terse`.
type PeerStatus struct {
	PublicKey       string
	Comment         string
	AllowedAddress  string
	EndpointAddress string
	RxBytes         int64
	TxBytes         int64
	LastHandshake   string // RouterOS duration string, e.g. "1m2s" or "never"
}

// GetPeerStatuses lists the live state of every peer on the configured
// WireGuard interface, used by the Status page instead of the local
// wgctrl device when the Mikrotik integration is Enabled.
func GetPeerStatuses(settings model.MikrotikSettings) ([]PeerStatus, error) {
	client, err := Dial(settings)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	ifName := settings.Interface
	if ifName == "" {
		ifName = defaultInterfaceName
	}

	out, err := run(client, fmt.Sprintf("/interface wireguard peers print terse where interface=%s", quote(ifName)))
	if err != nil {
		return nil, err
	}

	var peers []PeerStatus
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := parseTerseFields(line)
		if _, ok := fields["public-key"]; !ok {
			continue // not a data row (e.g. a header/footer line)
		}
		peers = append(peers, PeerStatus{
			PublicKey:       fields["public-key"],
			Comment:         fields["comment"],
			AllowedAddress:  fields["allowed-address"],
			EndpointAddress: fields["current-endpoint-address"],
			RxBytes:         parseInt64(fields["rx"]),
			TxBytes:         parseInt64(fields["tx"]),
			LastHandshake:   fields["last-handshake"],
		})
	}
	return peers, nil
}

var durationTokenRe = regexp.MustCompile(`(\d+)(w|d|h|ms|m|s)`)

// ParseDuration converts a RouterOS duration string (e.g. "1m2s", "3h4m5s",
// "never") into a time.Duration. Unrecognized input returns 0, false.
func ParseDuration(s string) (time.Duration, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "never" {
		return 0, false
	}
	var total time.Duration
	matched := false
	for _, m := range durationTokenRe.FindAllStringSubmatch(s, -1) {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		matched = true
		switch m[2] {
		case "w":
			total += time.Duration(n) * 7 * 24 * time.Hour
		case "d":
			total += time.Duration(n) * 24 * time.Hour
		case "h":
			total += time.Duration(n) * time.Hour
		case "m":
			total += time.Duration(n) * time.Minute
		case "s":
			total += time.Duration(n) * time.Second
		case "ms":
			total += time.Duration(n) * time.Millisecond
		}
	}
	return total, matched
}

func parseInt64(s string) int64 {
	var n int64
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0
		}
		n = n*10 + int64(ch-'0')
	}
	return n
}

// parseTerseFields tokenizes one line of RouterOS `print terse` output
// into its key=value fields, honoring double-quoted values. Leading
// tokens without an "=" (the record index, status flags) are skipped.
func parseTerseFields(line string) map[string]string {
	fields := make(map[string]string)
	i, n := 0, len(line)
	for i < n {
		for i < n && line[i] == ' ' {
			i++
		}
		if i >= n {
			break
		}
		start := i
		for i < n && line[i] != '=' && line[i] != ' ' {
			i++
		}
		if i >= n || line[i] != '=' {
			continue // bare token (index/flags), not a key=value pair
		}
		key := line[start:i]
		i++ // skip '='
		var val string
		if i < n && line[i] == '"' {
			i++
			valStart := i
			for i < n && line[i] != '"' {
				if line[i] == '\\' && i+1 < n {
					i++
				}
				i++
			}
			val = line[valStart:i]
			i++ // skip closing quote
		} else {
			valStart := i
			for i < n && line[i] != ' ' {
				i++
			}
			val = line[valStart:i]
		}
		fields[key] = val
	}
	return fields
}

// peerTag is the comment this app stamps on every peer it manages, so a
// later sync can find/update/remove exactly that client's entry.
func peerTag(clientID string) string {
	return "mtwg:" + clientID
}

// quote renders a Go string as a RouterOS script string literal.
func quote(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return "\"" + s + "\""
}

// ApplySync pushes the WireGuard server interface and every enabled
// client (as a tagged peer) to the Mikrotik device. It is safe to call
// repeatedly: existing peers are updated in place, clients that are no
// longer enabled have their peer removed, and anything on the interface
// that this app didn't create (comment not starting with "mtwg:") is
// left untouched.
func ApplySync(settings model.MikrotikSettings, server model.Server, clients []model.ClientData, globalSettings model.GlobalSetting) error {
	client, err := Dial(settings)
	if err != nil {
		return err
	}
	defer client.Close()

	ifName := settings.Interface
	if ifName == "" {
		ifName = defaultInterfaceName
	}

	var script strings.Builder

	// 1. Ensure the WireGuard interface exists with the current server
	//    key pair, listen port and MTU.
	ifArgs := fmt.Sprintf("private-key=%s listen-port=%d", quote(server.KeyPair.PrivateKey), server.Interface.ListenPort)
	if globalSettings.MTU > 0 {
		ifArgs += fmt.Sprintf(" mtu=%d", globalSettings.MTU)
	}
	fmt.Fprintf(&script, ":local ifId [/interface wireguard find where name=%s]\n", quote(ifName))
	fmt.Fprintf(&script, ":if ([:len $ifId] = 0) do={ /interface wireguard add name=%s %s } else={ /interface wireguard set $ifId %s }\n",
		quote(ifName), ifArgs, ifArgs)

	// 2. Upsert one peer per enabled client, keeping the "AllowedIPs on
	//    the server side = this client's own address space" convention
	//    already used by the local wg0.conf template.
	desiredTags := make(map[string]bool, len(clients))
	for _, cd := range clients {
		c := cd.Client
		if c == nil || !c.Enabled || c.PublicKey == "" {
			continue
		}
		tag := peerTag(c.ID)
		desiredTags[tag] = true

		allowed := append(append([]string{}, c.AllocatedIPs...), c.ExtraAllowedIPs...)
		setArgs := fmt.Sprintf("interface=%s public-key=%s allowed-address=%s comment=%s",
			quote(ifName), quote(c.PublicKey), quote(strings.Join(allowed, ",")), quote(tag))
		if c.PresharedKey != "" {
			setArgs += " preshared-key=" + quote(c.PresharedKey)
		}
		if globalSettings.PersistentKeepalive > 0 {
			setArgs += fmt.Sprintf(" persistent-keepalive=%ds", globalSettings.PersistentKeepalive)
		}

		fmt.Fprintf(&script, ":local pId [/interface wireguard peers find where comment=%s]\n", quote(tag))
		fmt.Fprintf(&script, ":if ([:len $pId] = 0) do={ /interface wireguard peers add %s } else={ /interface wireguard peers set $pId %s }\n", setArgs, setArgs)
	}

	if _, err := run(client, script.String()); err != nil {
		return err
	}

	// 3. Remove peers this app previously created for clients that are now
	//    disabled/deleted. The diff happens here in Go (not in a RouterOS
	//    script) to keep the logic simple and easy to get right: read back
	//    every "mtwg:"-tagged comment currently on the interface, then
	//    issue one targeted remove per tag that's no longer desired.
	out, err := run(client, fmt.Sprintf("/interface wireguard peers print terse where interface=%s", quote(ifName)))
	if err != nil {
		return err
	}
	var removeScript strings.Builder
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		comment := parseTerseFields(line)["comment"]
		if strings.HasPrefix(comment, "mtwg:") && !desiredTags[comment] {
			fmt.Fprintf(&removeScript, "/interface wireguard peers remove [find where comment=%s]\n", quote(comment))
		}
	}
	if removeScript.Len() == 0 {
		return nil
	}
	_, err = run(client, removeScript.String())
	return err
}
