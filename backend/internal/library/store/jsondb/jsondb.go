package jsondb

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/rs/xid"
	"github.com/sdomino/scribble"
	"github.com/skip2/go-qrcode"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/aldoexpert/mikrotik-wireguard/internal/library"
	"github.com/aldoexpert/mikrotik-wireguard/internal/model"
)

// JsonDB is the flat-file (JSON on disk) implementation of store.IStore.
type JsonDB struct {
	conn   *scribble.Driver
	dbPath string
}

// New returns a JsonDB rooted at dbPath.
func New(dbPath string) (*JsonDB, error) {
	conn, err := scribble.New(dbPath, nil)
	if err != nil {
		return nil, err
	}
	return &JsonDB{conn: conn, dbPath: dbPath}, nil
}

// Init creates the on-disk layout and seeds defaults (server keys, global
// settings, the initial admin user) on first run.
func (o *JsonDB) Init() error {
	clientPath := path.Join(o.dbPath, "clients")
	serverPath := path.Join(o.dbPath, "server")
	userPath := path.Join(o.dbPath, "users")
	wolPath := path.Join(o.dbPath, model.WakeOnLanHostCollectionName)
	interfacesPath := path.Join(o.dbPath, "interfaces")
	legacyServerInterfacePath := path.Join(serverPath, "interfaces.json")
	legacyServerKeyPairPath := path.Join(serverPath, "keypair.json")
	legacyGlobalSettingPath := path.Join(serverPath, "global_settings.json")
	hashesPath := path.Join(serverPath, "hashes.json")
	mikrotikSettingsPath := path.Join(serverPath, "mikrotik_settings.json")

	for _, p := range []string{clientPath, serverPath, userPath, wolPath, interfacesPath} {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			if err := os.MkdirAll(p, os.ModePerm); err != nil {
				return err
			}
		}
	}

	if _, err := os.Stat(hashesPath); os.IsNotExist(err) {
		h := &model.ClientServerHashes{Client: "none", Server: "none"}
		if err := o.conn.Write("server", "hashes", h); err != nil {
			return err
		}
		if err := library.ManagePerms(hashesPath); err != nil {
			return err
		}
	}

	if _, err := os.Stat(mikrotikSettingsPath); os.IsNotExist(err) {
		mikrotikSettings := &model.MikrotikSettings{
			Enabled:   false,
			Port:      lookupEnvOrInt("MTWG_MIKROTIK_PORT", defaultMikrotikPort),
			UpdatedAt: time.Now().UTC(),
		}
		if err := o.conn.Write("server", "mikrotik_settings", mikrotikSettings); err != nil {
			return err
		}
		if err := library.ManagePerms(mikrotikSettingsPath); err != nil {
			return err
		}
	}

	if err := o.migrateOrSeedDefaultInterface(legacyServerInterfacePath, legacyServerKeyPairPath, legacyGlobalSettingPath); err != nil {
		return err
	}

	results, err := o.conn.ReadAll("users")
	if err != nil || len(results) < 1 {
		user := &model.User{
			Username: lookupEnvOrString("MTWG_USERNAME", defaultUsername),
			Admin:    true,
		}
		user.PasswordHash = lookupEnvOrString("MTWG_PASSWORD_HASH", "")
		if user.PasswordHash == "" {
			user.PasswordHash = lookupEnvOrFile("MTWG_PASSWORD_HASH_FILE", "")
			if user.PasswordHash == "" {
				plaintext := lookupEnvOrString("MTWG_PASSWORD", defaultPassword)
				if plaintext == defaultPassword {
					plaintext = lookupEnvOrFile("MTWG_PASSWORD_FILE", defaultPassword)
				}
				hash, err := library.HashPassword(plaintext)
				if err != nil {
					return err
				}
				user.PasswordHash = hash
			}
		}

		if err := o.conn.Write("users", user.Username, user); err != nil {
			return err
		}
		results, _ = o.conn.ReadAll("users")
		if err := library.ManagePerms(path.Join(userPath, user.Username+".json")); err != nil {
			return err
		}
	}

	// warm the user checksum cache (used for JWT invalidation)
	for _, r := range results {
		user := model.User{}
		if err := json.Unmarshal(r, &user); err == nil {
			library.SetUserHash(user.Username, user)
		}
	}

	// warm the telegram userid -> client id cache
	clients, err := o.GetClients(false)
	if err != nil {
		return nil
	}
	for _, cl := range clients {
		client := cl.Client
		if client.Enabled && len(client.TgUserid) > 0 {
			if userid, err := strconv.ParseInt(client.TgUserid, 10, 64); err == nil {
				library.UpdateTgToClientID(userid, client.ID)
			}
		}
	}

	return nil
}

// legacyServerInterface/legacyServerKeyPair mirror the pre-multi-interface
// on-disk shape (model.ServerInterface/model.ServerKeypair have since been
// removed from the model package) -- kept here only so a database created
// by an older version of this app can be migrated once, on first start.
type legacyServerInterface struct {
	Addresses  []string  `json:"addresses"`
	ListenPort int       `json:"listen_port,string"`
	PostUp     string    `json:"post_up"`
	PreDown    string    `json:"pre_down"`
	PostDown   string    `json:"post_down"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type legacyServerKeypair struct {
	PrivateKey string    `json:"private_key"`
	PublicKey  string    `json:"public_key"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// legacyGlobalSetting mirrors the pre-multi-interface on-disk shape of
// server/global_settings.json (model.GlobalSetting has since been removed
// from the model package, since every one of its fields now lives on
// WgInterface instead) -- kept here only so a database created by an
// older version of this app can be migrated once, on first start.
type legacyGlobalSetting struct {
	EndpointAddress     string   `json:"endpoint_address"`
	DNSServers          []string `json:"dns_servers"`
	MTU                 int      `json:"mtu,string"`
	PersistentKeepalive int      `json:"persistent_keepalive,string"`
	FirewallMark        string   `json:"firewall_mark"`
	Table               string   `json:"table"`
	ConfigFilePath      string   `json:"config_file_path"`
}

// migrateOrSeedDefaultInterface runs once, on first start with an empty
// "interfaces" collection. If a pre-multi-interface database is found (the
// old single server/{interfaces,keypair,global_settings}.json files),
// their settings are carried over into one new WgInterface named
// "wireguard1", and every existing client is attached to it. Otherwise a
// fresh "wireguard1" interface is seeded from env vars, same as the old
// single-interface defaults.
func (o *JsonDB) migrateOrSeedDefaultInterface(legacyInterfacePath, legacyKeyPairPath, legacyGlobalSettingPath string) error {
	existing, err := o.GetInterfaces()
	if err == nil && len(existing) > 0 {
		return nil // already migrated/seeded
	}

	iface := model.WgInterface{
		ID:        xid.New().String(),
		Name:      "Default",
		WgName:    defaultMikrotikInterface, // "wireguard1"
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	if b, rerr := os.ReadFile(legacyGlobalSettingPath); rerr == nil {
		var lg legacyGlobalSetting
		_ = json.Unmarshal(b, &lg)
		iface.EndpointAddress = lg.EndpointAddress
		iface.DNSServers = lg.DNSServers
		iface.MTU = lg.MTU
		iface.PersistentKeepalive = lg.PersistentKeepalive
		iface.FirewallMark = lg.FirewallMark
		iface.Table = lg.Table
		iface.ConfigFilePath = lg.ConfigFilePath
	} else {
		endpointAddress := lookupEnvOrString("MTWG_ENDPOINT_ADDRESS", "")
		if endpointAddress == "" {
			publicInterface, err := library.GetPublicIP()
			if err != nil {
				return err
			}
			endpointAddress = publicInterface.IPAddress
		}
		iface.EndpointAddress = endpointAddress
		iface.DNSServers = lookupEnvOrStrings("MTWG_DNS", []string{defaultDNS})
		iface.MTU = lookupEnvOrInt("MTWG_MTU", defaultMTU)
		iface.PersistentKeepalive = lookupEnvOrInt("MTWG_PERSISTENT_KEEPALIVE", defaultPersistentKeepalive)
		iface.FirewallMark = lookupEnvOrString("MTWG_FIREWALL_MARK", defaultFirewallMark)
		iface.Table = lookupEnvOrString("MTWG_TABLE", defaultTable)
		iface.ConfigFilePath = lookupEnvOrString("MTWG_CONFIG_FILE_PATH", defaultConfigFilePath)
	}

	if _, err := os.Stat(legacyInterfacePath); err == nil {
		var li legacyServerInterface
		if b, rerr := os.ReadFile(legacyInterfacePath); rerr == nil {
			_ = json.Unmarshal(b, &li)
			iface.Config = model.WgInterfaceConfig{
				Addresses:  li.Addresses,
				ListenPort: li.ListenPort,
				PostUp:     li.PostUp,
				PreDown:    li.PreDown,
				PostDown:   li.PostDown,
				UpdatedAt:  li.UpdatedAt,
			}
		}
		if b, rerr := os.ReadFile(legacyKeyPairPath); rerr == nil {
			var lk legacyServerKeypair
			_ = json.Unmarshal(b, &lk)
			iface.KeyPair = model.WgInterfaceKeypair{
				PrivateKey: lk.PrivateKey,
				PublicKey:  lk.PublicKey,
				UpdatedAt:  lk.UpdatedAt,
			}
		}
	} else {
		key, kerr := wgtypes.GeneratePrivateKey()
		if kerr != nil {
			return kerr
		}
		iface.Config = model.WgInterfaceConfig{
			Addresses:  lookupEnvOrStrings("MTWG_SERVER_INTERFACE_ADDRESSES", []string{defaultServerAddress}),
			ListenPort: lookupEnvOrInt("MTWG_SERVER_LISTEN_PORT", defaultServerPort),
			PostUp:     lookupEnvOrString("MTWG_SERVER_POST_UP_SCRIPT", ""),
			PostDown:   lookupEnvOrString("MTWG_SERVER_POST_DOWN_SCRIPT", ""),
			UpdatedAt:  time.Now().UTC(),
		}
		iface.KeyPair = model.WgInterfaceKeypair{
			PrivateKey: key.String(),
			PublicKey:  key.PublicKey().String(),
			UpdatedAt:  time.Now().UTC(),
		}
	}

	if err := o.SaveInterface(iface); err != nil {
		return err
	}

	// Attach every pre-existing client (from a migrated database) to the
	// newly created interface.
	clients, err := o.GetClients(false)
	if err != nil {
		return nil
	}
	for _, cd := range clients {
		if cd.Client == nil || cd.Client.InterfaceID != "" {
			continue
		}
		c := *cd.Client
		c.InterfaceID = iface.ID
		if err := o.SaveClient(c); err != nil {
			return err
		}
	}

	return nil
}

func (o *JsonDB) GetUsers() ([]model.User, error) {
	var users []model.User
	results, err := o.conn.ReadAll("users")
	if err != nil {
		return users, err
	}
	for _, r := range results {
		user := model.User{}
		if err := json.Unmarshal(r, &user); err != nil {
			return users, fmt.Errorf("cannot decode user json structure: %v", err)
		}
		users = append(users, user)
	}
	return users, nil
}

func (o *JsonDB) GetUserByName(username string) (model.User, error) {
	user := model.User{}
	err := o.conn.Read("users", username, &user)
	return user, err
}

func (o *JsonDB) SaveUser(user model.User) error {
	userPath := path.Join(o.dbPath, "users", user.Username+".json")
	if err := o.conn.Write("users", user.Username, user); err != nil {
		return err
	}
	if err := library.ManagePerms(userPath); err != nil {
		return err
	}
	library.SetUserHash(user.Username, user)
	return nil
}

func (o *JsonDB) DeleteUser(username string) error {
	library.DeleteUserHash(username)
	return o.conn.Delete("users", username)
}

func (o *JsonDB) GetInterfaces() ([]model.WgInterface, error) {
	var out []model.WgInterface

	records, err := o.conn.ReadAll("interfaces")
	if err != nil {
		return out, err
	}
	for _, r := range records {
		var wi model.WgInterface
		if err := json.Unmarshal(r, &wi); err != nil {
			return out, fmt.Errorf("cannot decode interface json structure: %v", err)
		}
		out = append(out, wi)
	}
	return out, nil
}

func (o *JsonDB) GetInterfaceByID(id string) (model.WgInterface, error) {
	wi := model.WgInterface{}
	return wi, o.conn.Read("interfaces", id, &wi)
}

func (o *JsonDB) SaveInterface(iface model.WgInterface) error {
	p := path.Join(o.dbPath, "interfaces", iface.ID+".json")
	if err := o.conn.Write("interfaces", iface.ID, iface); err != nil {
		return err
	}
	return library.ManagePerms(p)
}

func (o *JsonDB) DeleteInterface(id string) error {
	return o.conn.Delete("interfaces", id)
}

func (o *JsonDB) GetMikrotikSettings() (model.MikrotikSettings, error) {
	settings := model.MikrotikSettings{}
	return settings, o.conn.Read("server", "mikrotik_settings", &settings)
}

func (o *JsonDB) SaveMikrotikSettings(settings model.MikrotikSettings) error {
	p := path.Join(o.dbPath, "server", "mikrotik_settings.json")
	if err := o.conn.Write("server", "mikrotik_settings", settings); err != nil {
		return err
	}
	return library.ManagePerms(p)
}

func (o *JsonDB) GetClients(hasQRCode bool) ([]model.ClientData, error) {
	var clients []model.ClientData

	records, err := o.conn.ReadAll("clients")
	if err != nil {
		return clients, err
	}

	for _, f := range records {
		client := model.Client{}
		clientData := model.ClientData{}

		if err := json.Unmarshal(f, &client); err != nil {
			return clients, fmt.Errorf("cannot decode client json structure: %v", err)
		}

		if hasQRCode && client.PrivateKey != "" && !client.IsUpstream() {
			iface, _ := o.GetInterfaceByID(client.InterfaceID)
			png, err := qrcode.Encode(library.BuildClientConfig(client, iface), qrcode.Medium, 256)
			if err == nil {
				clientData.QRCode = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
			}
		}

		clientData.Client = &client
		clients = append(clients, clientData)
	}

	return clients, nil
}

func (o *JsonDB) GetClientByID(clientID string, qrCodeSettings model.QRCodeSettings) (model.ClientData, error) {
	client := model.Client{}
	clientData := model.ClientData{}

	if err := o.conn.Read("clients", clientID, &client); err != nil {
		return clientData, err
	}

	if qrCodeSettings.Enabled && client.PrivateKey != "" && !client.IsUpstream() {
		iface, _ := o.GetInterfaceByID(client.InterfaceID)
		if !qrCodeSettings.IncludeDNS {
			iface.DNSServers = []string{}
		}
		if !qrCodeSettings.IncludeMTU {
			iface.MTU = 0
		}

		png, err := qrcode.Encode(library.BuildClientConfig(client, iface), qrcode.Medium, 256)
		if err == nil {
			clientData.QRCode = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
		}
	}

	clientData.Client = &client
	return clientData, nil
}

func (o *JsonDB) SaveClient(client model.Client) error {
	clientPath := path.Join(o.dbPath, "clients", client.ID+".json")
	err := o.conn.Write("clients", client.ID, client)
	if err == nil && client.Enabled && len(client.TgUserid) > 0 {
		if userid, perr := strconv.ParseInt(client.TgUserid, 10, 64); perr == nil {
			library.UpdateTgToClientID(userid, client.ID)
		}
	} else {
		library.RemoveTgToClientID(client.ID)
	}
	if err != nil {
		return err
	}
	return library.ManagePerms(clientPath)
}

func (o *JsonDB) DeleteClient(clientID string) error {
	library.RemoveTgToClientID(clientID)
	return o.conn.Delete("clients", clientID)
}

func (o *JsonDB) GetPath() string {
	return o.dbPath
}

func (o *JsonDB) GetHashes() (model.ClientServerHashes, error) {
	hashes := model.ClientServerHashes{}
	return hashes, o.conn.Read("server", "hashes", &hashes)
}

func (o *JsonDB) SaveHashes(hashes model.ClientServerHashes) error {
	p := path.Join(o.dbPath, "server", "hashes.json")
	if err := o.conn.Write("server", "hashes", hashes); err != nil {
		return err
	}
	return library.ManagePerms(p)
}
