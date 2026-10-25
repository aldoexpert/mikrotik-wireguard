package jsondb

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// Seed defaults used only the very first time the database is initialized.
const (
	defaultUsername            = "admin"
	defaultPassword            = "admin"
	defaultServerAddress       = "10.252.1.0/24"
	defaultServerPort          = 51820
	defaultDNS                 = "1.1.1.1"
	defaultMTU                 = 1450
	defaultPersistentKeepalive = 15
	defaultFirewallMark        = "0xca6c" // i.e. 51820
	defaultTable               = "auto"
	defaultConfigFilePath      = "/etc/wireguard/wg0.conf"
	defaultMikrotikPort        = 22
	defaultMikrotikInterface   = "wireguard1"
)

func lookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func lookupEnvOrInt(key string, defaultVal int) int {
	if val, ok := os.LookupEnv(key); ok {
		if v, err := strconv.Atoi(val); err == nil {
			return v
		}
	}
	return defaultVal
}

func lookupEnvOrStrings(key string, defaultVal []string) []string {
	if val, ok := os.LookupEnv(key); ok {
		return strings.Split(val, ",")
	}
	return defaultVal
}

func lookupEnvOrFile(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		if file, err := os.Open(val); err == nil {
			defer file.Close()
			var content string
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				content += scanner.Text()
			}
			return content
		}
	}
	return defaultVal
}
