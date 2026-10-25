package telegram

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/NicoNex/echotron/v3"
)

// OnConfigRequest is called when a client messages the bot asking for their
// config. It must return the names of any client it failed to send.
type OnConfigRequest func(userid int64) []string

type InitDependencies struct {
	OnConfigRequest OnConfigRequest
}

var (
	Token            string
	AllowConfRequest bool
	FloodWait        int

	bot      *echotron.API
	botMutex sync.RWMutex

	floodWaitMap     = make(map[int64]int64)
	floodMessageSent = make(map[int64]struct{})
)

// Start connects to the Telegram bot API and, if AllowConfRequest is set,
// polls for incoming messages so clients can self-serve their config.
// It blocks; call it in a goroutine and loop on its (non-fatal) error.
func Start(initDeps InitDependencies) (err error) {
	ticker := time.NewTicker(time.Minute)
	defer func() {
		if err != nil {
			botMutex.Lock()
			bot = nil
			botMutex.Unlock()
			ticker.Stop()
		}
		if r := recover(); r != nil {
			err = fmt.Errorf("[PANIC] recovered from panic: %v", r)
		}
	}()

	if Token == "" || len(Token) < 30 {
		return nil
	}

	b := echotron.NewAPI(Token)
	res, err := b.GetMe()
	if !res.Ok || err != nil {
		log.Printf("[TELEGRAM] Unable to connect to bot: %v %v", res.Description, err)
		return err
	}

	botMutex.Lock()
	bot = &b
	botMutex.Unlock()

	log.Printf("[TELEGRAM] Authorized as %s", res.Result.Username)

	go func() {
		for range ticker.C {
			updateFloodWait()
		}
	}()

	if !AllowConfRequest {
		return nil
	}

	updatesChan := echotron.PollingUpdatesOptions(Token, false, echotron.UpdateOptions{AllowedUpdates: []echotron.UpdateType{echotron.MessageUpdate}})
	for update := range updatesChan {
		if update.Message == nil {
			continue
		}
		userid := update.Message.Chat.ID
		if _, waiting := floodWaitMap[userid]; waiting {
			if _, notified := floodMessageSent[userid]; notified {
				continue
			}
			floodMessageSent[userid] = struct{}{}
			if _, sendErr := b.SendMessage(
				fmt.Sprintf("You can only request your configs once per %d minutes", FloodWait),
				userid,
				&echotron.MessageOptions{ReplyParameters: echotron.ReplyParameters{MessageID: update.Message.ID}},
			); sendErr != nil {
				log.Printf("[TELEGRAM] Failed to send message: %v", sendErr)
			}
			continue
		}
		floodWaitMap[userid] = time.Now().Unix()

		failed := initDeps.OnConfigRequest(userid)
		if len(failed) > 0 {
			messageText := "Failed to send configs:\n"
			for _, f := range failed {
				messageText += f + "\n"
			}
			if _, sendErr := b.SendMessage(messageText, userid, &echotron.MessageOptions{ReplyParameters: echotron.ReplyParameters{MessageID: update.Message.ID}}); sendErr != nil {
				log.Printf("[TELEGRAM] Failed to send message: %v", sendErr)
			}
		}
	}
	return nil
}

// SendConfig pushes a client's QR code + .conf file to their Telegram chat.
func SendConfig(userid int64, clientName string, confData, qrData []byte, ignoreFloodWait bool) error {
	botMutex.RLock()
	defer botMutex.RUnlock()

	if bot == nil {
		return fmt.Errorf("telegram bot is not configured or not available")
	}

	if _, waiting := floodWaitMap[userid]; waiting && !ignoreFloodWait {
		return fmt.Errorf("this client already got their config less than %d minutes ago", FloodWait)
	}
	if !ignoreFloodWait {
		floodWaitMap[userid] = time.Now().Unix()
	}

	if len(qrData) > 0 {
		qrAttachment := echotron.NewInputFileBytes("qr.png", qrData)
		if _, err := bot.SendPhoto(qrAttachment, userid, &echotron.PhotoOptions{Caption: clientName}); err != nil {
			return fmt.Errorf("unable to send qr picture: %w", err)
		}
	}

	confAttachment := echotron.NewInputFileBytes(clientName+".conf", confData)
	if _, err := bot.SendDocument(confAttachment, userid, nil); err != nil {
		return fmt.Errorf("unable to send conf file: %w", err)
	}
	return nil
}

func updateFloodWait() {
	threshold := time.Now().Unix() - 60*int64(FloodWait)
	for userid, ts := range floodWaitMap {
		if ts < threshold {
			delete(floodWaitMap, userid)
			delete(floodMessageSent, userid)
		}
	}
}
