# Black Synth DDoS Testing Tool

## Overview

This tool is designed for **authorized DDoS simulation and server resilience testing**. It can generate high volumes of traffic and protocol floods to help you understand how your server or application responds under stress. It also supports **automated post-attack payload deployment** for advanced durability testing.

---

## Features

- **HTTP GET/POST Floods:** Simulates application-layer attacks.
- **TCP SYN Flood:** Sends raw TCP SYN packets to test network stack resilience.
- **UDP Flood:** Floods target with UDP packets to test bandwidth and network handling.
- **ICMP Flood:** Sends ICMP echo requests (pings) for network stress.
- **Multi-URL & Multi-Worker:** Supports multiple targets and concurrent workers.
- **Telegram Reporting:** Sends detailed attack and payload deployment results to your Telegram chat.
- **Automated Payload Deployment:** After an attack, the tool can automatically attempt to upload and execute a resource-exhaustion script via SSH or HTTP (if enabled on the target).
- **Customizable:** Easily configure targets, workers, intervals, and cycles.

---

## Usage

1. **Configure your environment:**
   - Set `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` in your `.env` or environment variables.
   - (Optional) Set SSH credentials in the code for payload deployment via SSH.

2. **Run the tool:**

 - `go run ./cmd/server/main.go`


- Follow prompts to enter target URLs, number of workers, interval, and cycles.

3. **During the test:**
- The tool will execute HTTP, TCP, UDP, and ICMP floods against your targets.
- After each cycle, it will attempt to deploy a payload script (if SSH or HTTP upload is possible) that writes junk data to the server, simulating resource exhaustion.

4. **Reporting:**
- After each cycle and payload deployment, a summary is sent to your Telegram, including:
  - Attack statistics (requests sent, success/failure, average response time, etc.)
  - Payload deployment status (success/failure, number of payloads, MB sent)

---

## Example Telegram Report

   - ✅ Payload deployment SUCCESS on 192.168.1.100 - (This is the target IP)
   - Payloads deployed: 1
   - Total data sent: 0.98 MB

or

   - ❌ Payload deployment FAILED on 192.168.1.100
   - Error: ssh dial error: dial tcp 192.168.1.100:22: connect:   connection refused


---

## Ethical Notice

**This tool is for use only on servers and systems you own or have explicit permission to test. Unauthorized use is illegal and unethical.**

---

## Requirements

- Go latest version
- [gonum/plot](https://github.com/gonum/plot) for charting
- [golang.org/x/crypto/ssh](https://pkg.go.dev/golang.org/x/crypto/ssh) for SSH payload deployment
- Telegram bot and chat ID for notifications

---

## Customization

- **Payload script:** Edit the script in `DeployPayload` as needed for your test scenario.
- **Upload methods:** Modify SSH/HTTP upload logic as needed for your environment.
- **Attack parameters:** Tune workers, intervals, and cycles for your testing needs.

---

## Disclaimer

This tool is intended for research, learning, and authorized security assessment only. The author is not responsible for misuse or damage.
