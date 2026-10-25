package library

import (
	"bytes"
	"encoding/gob"
	"hash/crc32"
	"sync"

	"github.com/aldoexpert/mikrotik-wireguard/internal/model"
)

// DBUsersToCRC32 caches a checksum of every user record currently in the
// database. A JWT's embedded UserHash is compared against this cache on
// every request: if they differ, the user was changed or removed since the
// token was issued, so the session is rejected -- without needing a server
// side session store.
var (
	dbUsersToCRC32Mu sync.RWMutex
	dbUsersToCRC32   = map[string]uint32{}
)

// GetDBUserCRC32 computes a checksum of a user record.
func GetDBUserCRC32(user model.User) uint32 {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(user); err != nil {
		panic("model.User is gob-incompatible, session verification is impossible")
	}
	return crc32.ChecksumIEEE(buf.Bytes())
}

// SetUserHash records/updates the cached checksum for username.
func SetUserHash(username string, user model.User) {
	dbUsersToCRC32Mu.Lock()
	defer dbUsersToCRC32Mu.Unlock()
	dbUsersToCRC32[username] = GetDBUserCRC32(user)
}

// DeleteUserHash drops the cached checksum for username.
func DeleteUserHash(username string) {
	dbUsersToCRC32Mu.Lock()
	defer dbUsersToCRC32Mu.Unlock()
	delete(dbUsersToCRC32, username)
}

// UserHash returns the cached checksum for username, and whether it exists.
func UserHash(username string) (uint32, bool) {
	dbUsersToCRC32Mu.RLock()
	defer dbUsersToCRC32Mu.RUnlock()
	h, ok := dbUsersToCRC32[username]
	return h, ok
}

// --- Telegram userid -> client id mapping, used to let clients self-serve
// their config via the bot without re-exposing the whole client list.

var (
	tgUseridToClientIDMu sync.RWMutex
	tgUseridToClientID   = map[int64][]string{}
)

func AddTgToClientID(userid int64, clientID string) {
	tgUseridToClientIDMu.Lock()
	defer tgUseridToClientIDMu.Unlock()
	tgUseridToClientID[userid] = append(tgUseridToClientID[userid], clientID)
}

func UpdateTgToClientID(userid int64, clientID string) {
	tgUseridToClientIDMu.Lock()
	defer tgUseridToClientIDMu.Unlock()

	for uid, ids := range tgUseridToClientID {
		filtered := filterStringSlice(ids, clientID)
		if len(filtered) > 0 {
			tgUseridToClientID[uid] = filtered
		} else {
			delete(tgUseridToClientID, uid)
		}
	}
	tgUseridToClientID[userid] = append(tgUseridToClientID[userid], clientID)
}

func RemoveTgToClientID(clientID string) {
	tgUseridToClientIDMu.Lock()
	defer tgUseridToClientIDMu.Unlock()

	for uid, ids := range tgUseridToClientID {
		filtered := filterStringSlice(ids, clientID)
		if len(filtered) > 0 {
			tgUseridToClientID[uid] = filtered
		} else {
			delete(tgUseridToClientID, uid)
		}
	}
}

func ClientIDsForTelegramUser(userid int64) []string {
	tgUseridToClientIDMu.RLock()
	defer tgUseridToClientIDMu.RUnlock()
	return append([]string(nil), tgUseridToClientID[userid]...)
}

func filterStringSlice(s []string, excluded string) []string {
	filtered := s[:0]
	for _, v := range s {
		if v != excluded {
			filtered = append(filtered, v)
		}
	}
	return filtered
}
