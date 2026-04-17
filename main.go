package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"odysseyshield/internal/bot"
	"odysseyshield/internal/config"
	"odysseyshield/internal/storage"
)

func main() {
	cfgPath := "config.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	store := storage.New()

	b, err := bot.New(cfg, store)
	if err != nil {
		log.Fatalf("bot init: %v", err)
	}

	log.Println("Odyssey Shield (MVP) started")
	go b.Start()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
	b.Stop()
}
