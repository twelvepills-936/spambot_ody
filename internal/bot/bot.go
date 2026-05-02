package bot

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"odysseyshield/internal/config"
	"odysseyshield/internal/filter"
	"odysseyshield/internal/storage"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// Bot is the main Odyssey Shield bot.
type Bot struct {
	api    *tgbotapi.BotAPI
	cfg    *config.Config
	filter *filter.Filter
	store  *storage.Storage
	stop   chan struct{}
}

// New creates and connects the bot.
func New(cfg *config.Config, store *storage.Storage) (*Bot, error) {
	var httpClient *http.Client
	if cfg.ProxyURL != "" {
		proxyURL, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy_url: %w", err)
		}
		httpClient = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
		log.Printf("Using proxy: %s", cfg.ProxyURL)
	}

	var api *tgbotapi.BotAPI
	var err error
	if httpClient != nil {
		api, err = tgbotapi.NewBotAPIWithClient(cfg.BotToken, tgbotapi.APIEndpoint, httpClient)
	} else {
		api, err = tgbotapi.NewBotAPI(cfg.BotToken)
	}
	if err != nil {
		return nil, err
	}
	log.Printf("Authorised as @%s", api.Self.UserName)

	return &Bot{
		api:    api,
		cfg:    cfg,
		filter: filter.New(cfg, store),
		store:  store,
		stop:   make(chan struct{}),
	}, nil
}

// Start begins polling for updates. Blocks until Stop() is called.
// Deprecated: Use HandleUpdate for webhook mode.
func (b *Bot) Start() {
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := b.api.GetUpdatesChan(u)
	for {
		select {
		case upd := <-updates:
			b.handleUpdate(upd)
		case <-b.stop:
			return
		}
	}
}

// HandleUpdate processes a single update from webhook.
func (b *Bot) HandleUpdate(update tgbotapi.Update) {
	b.handleUpdate(update)
}

// Stop shuts down the update loop.
func (b *Bot) Stop() {
	b.api.StopReceivingUpdates()
	close(b.stop)
}

// SetWebhook sets the webhook URL for the bot.
func (b *Bot) SetWebhook(url string) error {
	config, err := tgbotapi.NewWebhook(url)
	if err != nil {
		return err
	}
	_, err = b.api.Request(config)
	return err
}
