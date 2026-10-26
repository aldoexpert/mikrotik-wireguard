package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/skip2/go-qrcode"

	"github.com/aldoexpert/mikrotik-wireguard/internal/config"
	"github.com/aldoexpert/mikrotik-wireguard/internal/core"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/emailer"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/store"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/store/jsondb"
	"github.com/aldoexpert/mikrotik-wireguard/internal/library/telegram"
	"github.com/aldoexpert/mikrotik-wireguard/internal/middleware"
	"github.com/aldoexpert/mikrotik-wireguard/internal/model"
	"github.com/aldoexpert/mikrotik-wireguard/internal/modules/auth"
	"github.com/aldoexpert/mikrotik-wireguard/internal/modules/network"
	"github.com/aldoexpert/mikrotik-wireguard/internal/modules/system"
	"github.com/aldoexpert/mikrotik-wireguard/internal/modules/users"
	"github.com/aldoexpert/mikrotik-wireguard/internal/modules/wireguard"
	"github.com/aldoexpert/mikrotik-wireguard/web"
)

// Set at build time via -ldflags, see backend/Makefile.
var (
	appVersion = "development"
	gitCommit  = "N/A"
	buildTime  = time.Now().UTC().Format("2006-01-02 15:04:05")
)

func main() {
	cfg := config.Load()
	cfg.AppVersion = appVersion
	cfg.GitCommit = gitCommit
	cfg.BuildTime = buildTime

	library.ParseSubnetRanges(cfg.SubnetRanges)
	telegram.Token = cfg.TelegramToken
	telegram.AllowConfRequest = cfg.TelegramAllowConfRequest
	telegram.FloodWait = cfg.TelegramFloodWait

	db, err := jsondb.New(cfg.DBPath)
	if err != nil {
		log.Fatalf("[FATAL] Could not open the database: %v", err)
	}
	if err := db.Init(); err != nil {
		log.Fatalf("[FATAL] Could not initialize the database: %v", err)
	}

	if err := library.ValidateAndFixSubnetRanges(db); err != nil {
		log.Fatalf("[FATAL] Invalid subnet ranges: %v", err)
	}
	if sr := library.GetSubnetRangesString(); sr != "" {
		log.Printf("[CONFIG] Active subnet ranges: %s", sr)
	}

	initServerConfigIfMissing(db, cfg.WgConfTemplate)

	mailer := buildEmailer(cfg)

	app := core.NewApp(cfg)
	auth.Register(app.Registry, cfg, db)
	wireguard.Register(app.Registry, cfg, db, mailer)
	network.Register(app.Registry, cfg, db)
	// Registered last so its menu group ("Administration") renders at the
	// bottom of the panel, after the domain modules above.
	users.Register(app.Registry, cfg, db)
	system.Register(app.Registry, cfg, db)

	go runTelegramBot(db)

	// Single port: known API module prefixes go to the dynamic router,
	// everything else (the SPA and its client-side routes) is served from
	// the embedded frontend build. See web/embed.go.
	mainMux := http.NewServeMux()
	for _, prefix := range []string{"/auth/", "/wireguard/", "/network/", "/users/", "/system/"} {
		mainMux.Handle(prefix, app.Router)
	}
	mainMux.Handle("/", web.Handler())

	var h http.Handler = mainMux
	h = middleware.Recovery(h)
	h = middleware.Logging(h)
	h = middleware.CORS(cfg.CORSAllowedOrigins)(h)
	log.Println("[APP] Middleware stack: CORS -> Logging -> Recovery -> Router")

	log.Println("[MAIN] Starting the application...")
	if err := app.Run(h); err != nil {
		log.Fatalf("[FATAL] Error running the application: %v", err)
	}
}

// initServerConfigIfMissing writes each interface's wg0.conf on first run,
// so a fresh install already has usable local config files before anyone
// logs in.
func initServerConfigIfMissing(db store.IStore, wgConfTemplate string) {
	ifaces, err := db.GetInterfaces()
	if err != nil {
		log.Fatalf("[FATAL] Could not get the interface list: %v", err)
	}
	clients, err := db.GetClients(false)
	if err != nil {
		log.Fatalf("[FATAL] Could not get the client configuration: %v", err)
	}
	dbUsers, err := db.GetUsers()
	if err != nil {
		log.Fatalf("[FATAL] Could not get the user configuration: %v", err)
	}

	for _, iface := range ifaces {
		if _, err := os.Stat(iface.ConfigFilePath); err == nil {
			continue // already exists, don't overwrite it implicitly
		}

		var scoped []model.ClientData
		for _, cd := range clients {
			if cd.Client != nil && cd.Client.InterfaceID == iface.ID {
				scoped = append(scoped, cd)
			}
		}

		if err := library.WriteWireGuardServerConfig(wgConfTemplate, iface, scoped, dbUsers); err != nil {
			log.Fatalf("[FATAL] Could not create the %s configuration: %v", iface.WgName, err)
		}
	}
}

func buildEmailer(cfg *config.App) emailer.Emailer {
	if cfg.SendgridApiKey != "" {
		return emailer.NewSendgridApiMail(cfg.SendgridApiKey, cfg.EmailFromName, cfg.EmailFrom)
	}
	return emailer.NewSmtpMail(
		cfg.SmtpHostname, cfg.SmtpPort, cfg.SmtpUsername, cfg.SmtpPassword, cfg.SmtpHelo,
		cfg.SmtpNoTLSCheck, cfg.SmtpAuthType, cfg.EmailFromName, cfg.EmailFrom, cfg.SmtpEncryption,
	)
}

// runTelegramBot keeps (re)connecting the bot forever; Start returns nil
// only when no token is configured.
func runTelegramBot(db store.IStore) {
	deps := telegram.InitDependencies{
		OnConfigRequest: func(userid int64) []string {
			return sendRequestedConfigsToTelegram(db, userid)
		},
	}
	for {
		if err := telegram.Start(deps); err == nil {
			break
		}
	}
}

// sendRequestedConfigsToTelegram handles an inbound "send me my config(s)"
// request from the Telegram bot, returning the names of any client it
// failed to send.
func sendRequestedConfigsToTelegram(db store.IStore, userid int64) []string {
	failed := make([]string, 0)

	for _, clientID := range library.ClientIDsForTelegramUser(userid) {
		clientData, err := db.GetClientByID(clientID, model.QRCodeSettings{Enabled: true, IncludeDNS: true, IncludeMTU: true})
		if err != nil {
			failed = append(failed, clientID)
			continue
		}

		iface, _ := db.GetInterfaceByID(clientData.Client.InterfaceID)
		conf := library.BuildClientConfig(*clientData.Client, iface)

		var qrData []byte
		if clientData.Client.PrivateKey != "" {
			var err error
			qrData, err = qrcode.Encode(conf, qrcode.Medium, 512)
			if err != nil {
				failed = append(failed, clientData.Client.Name)
				continue
			}
		}

		if err := telegram.SendConfig(userid, clientData.Client.Name, []byte(conf), qrData, true); err != nil {
			failed = append(failed, clientData.Client.Name)
			continue
		}
		time.Sleep(2 * time.Second)
	}

	return failed
}
