package store

import "github.com/aldoexpert/mikrotik-wireguard/internal/model"

// IStore is the persistence contract for the whole application. The only
// implementation today is jsondb (flat JSON files on disk); it is kept as
// an interface so a future storage backend can be swapped in without
// touching the modules that consume it.
type IStore interface {
	Init() error

	GetUsers() ([]model.User, error)
	GetUserByName(username string) (model.User, error)
	SaveUser(user model.User) error
	DeleteUser(username string) error

	GetInterfaces() ([]model.WgInterface, error)
	GetInterfaceByID(id string) (model.WgInterface, error)
	SaveInterface(iface model.WgInterface) error
	DeleteInterface(id string) error

	GetMikrotikSettings() (model.MikrotikSettings, error)
	SaveMikrotikSettings(settings model.MikrotikSettings) error

	GetClients(hasQRCode bool) ([]model.ClientData, error)
	GetClientByID(clientID string, qrCode model.QRCodeSettings) (model.ClientData, error)
	SaveClient(client model.Client) error
	DeleteClient(clientID string) error

	GetWakeOnLanHosts() ([]model.WakeOnLanHost, error)
	GetWakeOnLanHost(macAddress string) (*model.WakeOnLanHost, error)
	SaveWakeOnLanHost(host model.WakeOnLanHost) error
	DeleteWakeOnHostLanHost(macAddress string) error
	DeleteWakeOnHost(host model.WakeOnLanHost) error

	GetPath() string
	SaveHashes(hashes model.ClientServerHashes) error
	GetHashes() (model.ClientServerHashes, error)
}
