package library

import (
	"embed"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"text/template"

	"golang.org/x/mod/sumdb/dirhash"

	"github.com/aldoexpert/mikrotik-wireguard/internal/library/store"
	"github.com/aldoexpert/mikrotik-wireguard/internal/model"
)

func lookupEnvOrStrings(key string, defaultVal []string) []string {
	if val, ok := os.LookupEnv(key); ok {
		return strings.Split(val, ",")
	}
	return defaultVal
}

func lookupEnvOrBool(key string, defaultVal bool) bool {
	if val, ok := os.LookupEnv(key); ok {
		return val == "1" || strings.EqualFold(val, "true")
	}
	return defaultVal
}

//go:embed templates/wg.conf.tmpl
var embeddedTemplates embed.FS

// BuildClientConfig renders the wg-quick [Interface]/[Peer] config a client
// downloads/emails/scans as a QR code to connect to the server. Only
// meaningful for an "allowed client" (see Client.IsUpstream) -- an
// upstream/"Connect To" record has no private key of its own to hand out.
func BuildClientConfig(client model.Client, iface model.WgInterface) string {
	clientAddress := fmt.Sprintf("Address = %s\n", strings.Join(client.AllocatedIPs, ","))
	clientPrivateKey := fmt.Sprintf("PrivateKey = %s\n", client.PrivateKey)
	clientDNS := ""
	if client.UseServerDNS {
		clientDNS = fmt.Sprintf("DNS = %s\n", strings.Join(iface.DNSServers, ","))
	}
	clientMTU := ""
	if iface.MTU > 0 {
		clientMTU = fmt.Sprintf("MTU = %d\n", iface.MTU)
	}

	peerPublicKey := fmt.Sprintf("PublicKey = %s\n", iface.KeyPair.PublicKey)
	peerPresharedKey := ""
	if client.PresharedKey != "" {
		peerPresharedKey = fmt.Sprintf("PresharedKey = %s\n", client.PresharedKey)
	}

	peerAllowedIPs := fmt.Sprintf("AllowedIPs = %s\n", strings.Join(client.AllowedIPs, ","))

	desiredHost := iface.EndpointAddress
	desiredPort := iface.Config.ListenPort
	if strings.Contains(desiredHost, ":") {
		split := strings.Split(desiredHost, ":")
		desiredHost = split[0]
		if n, err := strconv.Atoi(split[1]); err == nil {
			desiredPort = n
		}
	}
	peerEndpoint := fmt.Sprintf("Endpoint = %s:%d\n", desiredHost, desiredPort)

	peerPersistentKeepalive := ""
	if iface.PersistentKeepalive > 0 {
		peerPersistentKeepalive = fmt.Sprintf("PersistentKeepalive = %d\n", iface.PersistentKeepalive)
	}

	return "[Interface]\n" +
		clientAddress +
		clientPrivateKey +
		clientDNS +
		clientMTU +
		"\n[Peer]\n" +
		peerPublicKey +
		peerPresharedKey +
		peerAllowedIPs +
		peerEndpoint +
		peerPersistentKeepalive
}

// WriteWireGuardServerConfig renders and writes one interface's wg0.conf
// (or the custom template at wgConfTemplate, if given) to
// iface.ConfigFilePath. clientDataList should already be filtered to just
// this interface's clients -- every enabled one becomes a [Peer] block,
// whether it's an allowed client (no Endpoint) or an upstream "Connect To"
// peer (Endpoint set): wg-quick treats both identically, the Endpoint
// field is what makes this side dial out to it.
func WriteWireGuardServerConfig(wgConfTemplate string, iface model.WgInterface, clientDataList []model.ClientData, usersList []model.User) error {
	var tmplContent string

	if wgConfTemplate != "" {
		b, err := os.ReadFile(wgConfTemplate)
		if err != nil {
			return err
		}
		tmplContent = string(b)
	} else {
		b, err := embeddedTemplates.ReadFile("templates/wg.conf.tmpl")
		if err != nil {
			return err
		}
		tmplContent = string(b)
	}

	// escape multiline notes so they stay valid comment lines
	escaped := make([]model.ClientData, 0, len(clientDataList))
	for _, cd := range clientDataList {
		if cd.Client.AdditionalNotes != "" {
			cd.Client.AdditionalNotes = strings.ReplaceAll(cd.Client.AdditionalNotes, "\n", "\n# ")
		}
		escaped = append(escaped, cd)
	}

	t, err := template.New("wg_config").Parse(tmplContent)
	if err != nil {
		return err
	}

	f, err := os.Create(iface.ConfigFilePath)
	if err != nil {
		return err
	}
	defer f.Close()

	data := map[string]interface{}{
		"iface":          iface,
		"clientDataList": escaped,
		"usersList":      usersList,
	}

	return t.Execute(f, data)
}

// ClientDefaultsFromEnv reads the suggested defaults for a new client.
func ClientDefaultsFromEnv() model.ClientDefaults {
	return model.ClientDefaults{
		AllowedIps:          lookupEnvOrStrings("MTWG_DEFAULT_CLIENT_ALLOWED_IPS", []string{"0.0.0.0/0"}),
		ExtraAllowedIps:     lookupEnvOrStrings("MTWG_DEFAULT_CLIENT_EXTRA_ALLOWED_IPS", []string{}),
		UseServerDNS:        lookupEnvOrBool("MTWG_DEFAULT_CLIENT_USE_SERVER_DNS", true),
		EnableAfterCreation: lookupEnvOrBool("MTWG_DEFAULT_CLIENT_ENABLE_AFTER_CREATION", true),
	}
}

// GetCurrentHash fingerprints the on-disk client/interface config
// directories, used to detect changes that still need to be "applied".
func GetCurrentHash(db store.IStore) (string, string) {
	hashClients, _ := dirhash.HashDir(path.Join(db.GetPath(), "clients"), "prefix", dirhash.Hash1)
	hashInterfaces, _ := dirhash.HashDir(path.Join(db.GetPath(), "interfaces"), "prefix", dirhash.Hash1)
	return hashClients, hashInterfaces
}

func HashesChanged(db store.IStore) bool {
	old, _ := db.GetHashes()
	newClient, newServer := GetCurrentHash(db)
	return old.Client != newClient || old.Server != newServer
}

func UpdateHashes(db store.IStore) error {
	var h model.ClientServerHashes
	h.Client, h.Server = GetCurrentHash(db)
	return db.SaveHashes(h)
}

// ManagePerms restricts a data file's permissions to the owner only -- the
// database directory holds private keys and password hashes.
func ManagePerms(path string) error {
	return os.Chmod(path, 0600)
}
