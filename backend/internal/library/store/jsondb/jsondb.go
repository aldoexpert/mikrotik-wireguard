package jsondb

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strconv"
	"time"

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
	serverInterfacePath := path.Join(serverPath, "interfaces.json")
	serverKeyPairPath := path.Join(serverPath, "keypair.json")
	globalSettingPath := path.Join(serverPath, "global_settings.json")
	hashesPath := path.Join(serverPath, "hashes.json")
	mikrotikSettingsPath := path.Join(serverPath, "mikrotik_settings.json")

	for _, p := range []string{clientPath, serverPath, userPath, wolPath} {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			if err := os.MkdirAll(p, os.ModePerm); err != nil {
				return err
			}
		}
	}

	if _, err := os.Stat(serverInterfacePath); os.IsNotExist(err) {
		serverInterface := &model.ServerInterface{
			Addresses:  lookupEnvOrStrings("MTWG_SERVER_INTERFACE_ADDRESSES", []string{defaultServerAddress}),
			ListenPort: lookupEnvOrInt("MTWG_SERVER_LISTEN_PORT", defaultServerPort),
			PostUp:     lookupEnvOrString("MTWG_SERVER_POST_UP_SCRIPT", ""),
			PostDown:   lookupEnvOrString("MTWG_SERVER_POST_DOWN_SCRIPT", ""),
			UpdatedAt:  time.Now().UTC(),
		}
		if err := o.conn.Write("server", "interfaces", serverInterface); err != nil {
			return err
		}
		if err := library.ManagePerms(serverInterfacePath); err != nil {
			return err
		}
	}

	if _, err := os.Stat(serverKeyPairPath); os.IsNotExist(err) {
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return err
		}
		serverKeyPair := &model.ServerKeypair{
			PrivateKey: key.String(),
			PublicKey:  key.PublicKey().String(),
			UpdatedAt:  time.Now().UTC(),
		}
		if err := o.conn.Write("server", "keypair", serverKeyPair); err != nil {
			return err
		}
		if err := library.ManagePerms(serverKeyPairPath); err != nil {
			return err
		}
	}

	if _, err := os.Stat(globalSettingPath); os.IsNotExist(err) {
		endpointAddress := lookupEnvOrString("MTWG_ENDPOINT_ADDRESS", "")
		if endpointAddress == "" {
			publicInterface, err := library.GetPublicIP()
			if err != nil {
				return err
			}
			endpointAddress = publicInterface.IPAddress
		}

		globalSetting := &model.GlobalSetting{
			EndpointAddress:     endpointAddress,
			DNSServers:          lookupEnvOrStrings("MTWG_DNS", []string{defaultDNS}),
			MTU:                 lookupEnvOrInt("MTWG_MTU", defaultMTU),
			PersistentKeepalive: lookupEnvOrInt("MTWG_PERSISTENT_KEEPALIVE", defaultPersistentKeepalive),
			FirewallMark:        lookupEnvOrString("MTWG_FIREWALL_MARK", defaultFirewallMark),
			Table:               lookupEnvOrString("MTWG_TABLE", defaultTable),
			ConfigFilePath:      lookupEnvOrString("MTWG_CONFIG_FILE_PATH", defaultConfigFilePath),
			UpdatedAt:           time.Now().UTC(),
		}
		if err := o.conn.Write("server", "global_settings", globalSetting); err != nil {
			return err
		}
		if err := library.ManagePerms(globalSettingPath); err != nil {
			return err
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
			Interface: lookupEnvOrString("MTWG_MIKROTIK_INTERFACE", defaultMikrotikInterface),
			UpdatedAt: time.Now().UTC(),
		}
		if err := o.conn.Write("server", "mikrotik_settings", mikrotikSettings); err != nil {
			return err
		}
		if err := library.ManagePerms(mikrotikSettingsPath); err != nil {
			return err
		}
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

func (o *JsonDB) GetGlobalSettings() (model.GlobalSetting, error) {
	settings := model.GlobalSetting{}
	return settings, o.conn.Read("server", "global_settings", &settings)
}

func (o *JsonDB) SaveGlobalSettings(globalSettings model.GlobalSetting) error {
	p := path.Join(o.dbPath, "server", "global_settings.json")
	if err := o.conn.Write("server", "global_settings", globalSettings); err != nil {
		return err
	}
	return library.ManagePerms(p)
}

func (o *JsonDB) GetServer() (model.Server, error) {
	server := model.Server{}

	serverInterface := model.ServerInterface{}
	if err := o.conn.Read("server", "interfaces", &serverInterface); err != nil {
		return server, err
	}

	serverKeyPair := model.ServerKeypair{}
	if err := o.conn.Read("server", "keypair", &serverKeyPair); err != nil {
		return server, err
	}

	server.Interface = &serverInterface
	server.KeyPair = &serverKeyPair
	return server, nil
}

func (o *JsonDB) SaveServerInterface(serverInterface model.ServerInterface) error {
	p := path.Join(o.dbPath, "server", "interfaces.json")
	if err := o.conn.Write("server", "interfaces", serverInterface); err != nil {
		return err
	}
	return library.ManagePerms(p)
}

func (o *JsonDB) SaveServerKeyPair(serverKeyPair model.ServerKeypair) error {
	p := path.Join(o.dbPath, "server", "keypair.json")
	if err := o.conn.Write("server", "keypair", serverKeyPair); err != nil {
		return err
	}
	return library.ManagePerms(p)
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

		if hasQRCode && client.PrivateKey != "" {
			server, _ := o.GetServer()
			globalSettings, _ := o.GetGlobalSettings()
			png, err := qrcode.Encode(library.BuildClientConfig(client, server, globalSettings), qrcode.Medium, 256)
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

	if qrCodeSettings.Enabled && client.PrivateKey != "" {
		server, _ := o.GetServer()
		globalSettings, _ := o.GetGlobalSettings()
		if !qrCodeSettings.IncludeDNS {
			globalSettings.DNSServers = []string{}
		}
		if !qrCodeSettings.IncludeMTU {
			globalSettings.MTU = 0
		}

		png, err := qrcode.Encode(library.BuildClientConfig(client, server, globalSettings), qrcode.Medium, 256)
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
