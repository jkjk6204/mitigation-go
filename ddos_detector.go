package main

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Constants for DDoS detection
const (
	threshold           = 100 // Adjust this threshold based on your network's typical traffic rate
	detectionInterval   = 60  // Time interval (in seconds) for detecting DDoS attacks
	iptablesCmd         = "iptables"
	iptablesRuleCommand = "-I"
	iptablesChain       = "INPUT"
	iptablesAction      = "-j DROP"
)

var trafficCounts = make(map[string]int)

// blockIP blocks incoming traffic from a specific IP address
func blockIP(ipAddress string) {
	cmd := exec.Command(iptablesCmd, iptablesRuleCommand, iptablesChain, "-s", ipAddress, iptablesAction)
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error blocking IP:", err)
	}
	fmt.Printf("Blocked incoming traffic from %s\n", ipAddress)
}

// detectAndMitigateDDoS detects and mitigates DDoS attacks
func detectAndMitigateDDoS() {
	for {
		currentTime := time.Now()
		for ip, count := range trafficCounts {
			// If traffic count exceeds the threshold, block the IP
			if count > threshold {
				blockIP(ip)
				delete(trafficCounts, ip)
				fmt.Printf("DDoS detected from %s. Blocked.\n", ip)
			} else {
				trafficCounts[ip] = 0
			}
		}
		time.Sleep(detectionInterval * time.Second)
	}
}

func main() {
	// Start the DDoS detection loop in the background
	go detectAndMitigateDDoS()

	for {
		fmt.Println("Select an option:")
		fmt.Println("1. Block IP address")
		fmt.Println("2. Block port")
		fmt.Println("3. Exit")

		var choice string
		fmt.Print("Enter your choice: ")
		fmt.Scanln(&choice)

		switch choice {
		case "1":
			var ipToBlock string
			fmt.Print("Enter the IP address to block: ")
			fmt.Scanln(&ipToBlock)
			blockIP(strings.TrimSpace(ipToBlock))
		case "2":
			var portToBlock string
			fmt.Print("Enter the port to block: ")
			fmt.Scanln(&portToBlock)
			// Block port logic can be added here
			fmt.Println("Blocking port is not implemented in this example.")
		case "3":
			return
		default:
			fmt.Println("Invalid choice. Please select a valid option.")
		}
	}
}
