package system

import (
	"net/http"

	"github.com/aldoexpert/mikrotik-wireguard/internal/config"
	"github.com/aldoexpert/mikrotik-wireguard/internal/core"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/store"
	"github.com/aldoexpert/mikrotik-wireguard/internal/model"
)

type MiscController struct {
	cfg *config.App
	db  store.IStore
}

func NewMiscController(cfg *config.App, db store.IStore) *MiscController {
	return &MiscController{cfg: cfg, db: db}
}

// Health is a simple liveness probe for docker/orchestrator health checks.
func (c *MiscController) Health(w http.ResponseWriter, r *http.Request, params []string) {
	core.Success(w, "ok", nil)
}

type aboutResponse struct {
	AppName      string `json:"app_name"`
	AppVersion   string `json:"app_version"`
	GitCommit    string `json:"git_commit"`
	BuildTime    string `json:"build_time"`
	LoginEnabled bool   `json:"login_enabled"`
}

// About returns basic build/version info for the frontend's About page.
func (c *MiscController) About(w http.ResponseWriter, r *http.Request, params []string) {
	core.Success(w, "", aboutResponse{
		AppName:      c.cfg.Name,
		AppVersion:   c.cfg.AppVersion,
		GitCommit:    c.cfg.GitCommit,
		BuildTime:    c.cfg.BuildTime,
		LoginEnabled: !c.cfg.DisableLogin,
	})
}

// MachineIPs returns the server's own local + public IP addresses, to help
// an admin fill in the WireGuard endpoint address.
func (c *MiscController) MachineIPs(w http.ResponseWriter, r *http.Request, params []string) {
	list, err := library.GetInterfaceIPs()
	if err != nil {
		core.InternalError(w, "Could not get the machine's IP addresses", err)
		return
	}

	if publicIP, err := library.GetPublicIP(); err == nil {
		list = append([]model.Interface{publicIP}, list...)
	}

	core.SuccessList(w, "", list)
}

// SubnetRanges returns the ordered list of named subnet ranges configured
// via MTWG_SUBNET_RANGES.
func (c *MiscController) SubnetRanges(w http.ResponseWriter, r *http.Request, params []string) {
	core.SuccessList(w, "", library.SubnetRangesOrder)
}

// HashesChanged reports whether the client/server config on disk differs
// from what was last "applied".
func (c *MiscController) HashesChanged(w http.ResponseWriter, r *http.Request, params []string) {
	core.Success(w, "", library.HashesChanged(c.db))
}
