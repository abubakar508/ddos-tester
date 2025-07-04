package main

import (
	"context"
	"ddos/internal/ddos"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables from .env file if present
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, relying on environment variables")
	}

	targetURLsStr := os.Getenv("TARGET_URLS")
	if targetURLsStr == "" {
		log.Fatal("TARGET_URLS is required (comma-separated URLs)")
	}
	targetURLs := strings.Split(targetURLsStr, ",")

	workers := 100 // default
	if wStr := os.Getenv("WORKERS"); wStr != "" {
		if w, err := strconv.Atoi(wStr); err == nil && w > 0 {
			workers = w
		} else {
			log.Printf("Invalid WORKERS env var '%s', using default %d", wStr, workers)
		}
	}

	interval := 30 * time.Minute
	if iStr := os.Getenv("INTERVAL_MINUTES"); iStr != "" {
		if i, err := strconv.Atoi(iStr); err == nil && i > 0 {
			interval = time.Duration(i) * time.Minute
		} else {
			log.Printf("Invalid INTERVAL_MINUTES env var '%s', using default %s", iStr, interval)
		}
	}

	cycles := 12 // default 12 cycles = 6 hours
	if cStr := os.Getenv("CYCLES"); cStr != "" {
		if c, err := strconv.Atoi(cStr); err == nil && c > 0 {
			cycles = c
		} else {
			log.Printf("Invalid CYCLES env var '%s', using default %d", cStr, cycles)
		}
	}

	// Read Telegram config from env
	tgBotToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	if tgBotToken == "" {
		log.Fatal("TELEGRAM_BOT_TOKEN is required")
	}

	tgChatIDStr := os.Getenv("TELEGRAM_CHAT_ID")
	if tgChatIDStr == "" {
		log.Fatal("TELEGRAM_CHAT_ID is required")
	}
	tgChatID, err := strconv.ParseInt(tgChatIDStr, 10, 64)
	if err != nil {
		log.Fatalf("Invalid TELEGRAM_CHAT_ID '%s': %v", tgChatIDStr, err)
	}

	// Since mailer is no longer used, pass nil or dummy mailer
	tester, err := ddos.NewDDoSTester(targetURLs, workers, nil, "", tgBotToken, tgChatID)
	if err != nil {
		log.Fatalf("Failed to create DDoS tester: %v", err)
	}

	log.Printf("Starting scheduled DDoS test on %v with %d workers, interval %s, cycles %d", targetURLs, workers, interval, cycles)

	if err := tester.RunScheduled(context.Background(), interval, cycles); err != nil {
		log.Fatalf("Scheduled DDoS test failed: %v", err)
	}

	log.Println("Scheduled DDoS test completed successfully")
}
