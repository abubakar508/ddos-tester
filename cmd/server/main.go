package main

import (
	"bufio"
	"context"
	"ddos/internal/ddos"
	"fmt"
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

	printIntroduction()

	// Prompt user for target URLs (comma-separated)
	targetURLs := promptForTargetURLs("Enter target URLs (comma-separated, e.g. http://example.com,http://test.com): ")

	// Default workers
	defaultWorkers := 100

	// Try to get workers from env var if valid
	if wStr := os.Getenv("WORKERS"); wStr != "" {
		if w, err := strconv.Atoi(wStr); err == nil && w > 0 {
			defaultWorkers = w
		} else {
			log.Printf("Invalid WORKERS env var '%s', using default %d", wStr, defaultWorkers)
		}
	}

	// Prompt user for number of workers
	workers := promptForInt(fmt.Sprintf("Enter number of workers (default %d): ", defaultWorkers), defaultWorkers)

	// Prompt user for interval in minutes
	interval := promptForDuration("Enter interval between cycles in minutes (default 30): ", 1)

	// Prompt user for number of cycles
	cycles := promptForInt("Enter number of cycles (default 12): ", 3)

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

// printIntroduction displays tool info and disclaimer
func printIntroduction() {
	// 	asciiArt := `
	//  ____  _            _            _____             _       _
	// | __ )| | __ _  ___| | _____    | ____|_ __   __ _| |_ ___| |__
	// |  _ \| |/ _` + "`" + ` |/ __| |/ / __|   |  _| | '_ \ / _` + "`" + ` | __/ __| '_ \
	// | |_) | | (_| | (__|   <\__ \   | |___| | | | (_| | || (__| | | |
	// |____/|_|\__,_|\___|_|\_\___/   |_____|_| |_|\__,_|\__\___|_| |_|

	// `

	// fmt.Println(asciiArt)

	fmt.Println("--------------------------------------------------")
	fmt.Println("                 DDoS Testing Tool v1.0")
	fmt.Println("              Created by: Abubakar Ismail")
	fmt.Println()
	fmt.Println("Purpose:")
	fmt.Println("  Tool to simulate DDoS attacks for testing and")
	fmt.Println("  security assessment only.")
	fmt.Println()
	fmt.Println("DISCLAIMER:")
	fmt.Println("  This tool is intended for authorized testing only.")
	fmt.Println("  Unauthorized use against systems without permission")
	fmt.Println("  is illegal and unethical. Use responsibly.")
	fmt.Println("--------------------------------------------------")
	fmt.Println()
}

// promptForTargetURLs prompts user to enter one or more target URLs
func promptForTargetURLs(prompt string) []string {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(prompt)
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Error reading input: %v", err)
			continue
		}
		input = strings.TrimSpace(input)
		if input == "" {
			fmt.Println("Please enter at least one target URL.")
			continue
		}
		urls := strings.Split(input, ",")
		// Basic validation: check that each URL starts with http:// or https://
		valid := true
		for _, u := range urls {
			u = strings.TrimSpace(u)
			if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
				fmt.Printf("Invalid URL (missing scheme): %s\n", u)
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		// Trim spaces and return
		for i := range urls {
			urls[i] = strings.TrimSpace(urls[i])
		}
		return urls
	}
}

// promptForDuration prompts the user to enter a duration in minutes.
// Returns defaultVal if input is empty or invalid.
func promptForDuration(prompt string, defaultVal int) time.Duration {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(prompt)
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Error reading input: %v", err)
			return time.Duration(defaultVal) * time.Minute
		}
		input = strings.TrimSpace(input)
		if input == "" {
			return time.Duration(defaultVal) * time.Minute
		}
		minutes, err := strconv.Atoi(input)
		if err != nil || minutes <= 0 {
			fmt.Println("Please enter a positive integer for minutes.")
			continue
		}
		return time.Duration(minutes) * time.Minute
	}
}

// promptForInt prompts the user to enter an integer.
// Returns defaultVal if input is empty or invalid.
func promptForInt(prompt string, defaultVal int) int {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(prompt)
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Error reading input: %v", err)
			return defaultVal
		}
		input = strings.TrimSpace(input)
		if input == "" {
			return defaultVal
		}
		val, err := strconv.Atoi(input)
		if err != nil || val <= 0 {
			fmt.Println("Please enter a positive integer.")
			continue
		}
		return val
	}
}
