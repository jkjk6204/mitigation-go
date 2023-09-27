package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Constants for DDoS detection
const (
	// Adjust these threshold values based on your network's typical traffic rate
	tcpThreshold          = 200   // Threshold for TCP connections
	udpThreshold          = 100   // Threshold for UDP connections
	httpsThreshold        = 50    // Threshold for HTTPS connections (adjust as needed)
	smtpThreshold         = 30    // Threshold for SMTP connections
	ftpThreshold          = 20    // Threshold for FTP connections
	telnetThreshold       = 10    // Threshold for TELNET connections
	pop3Threshold         = 15    // Threshold for POP3 connections
	imapThreshold         = 15    // Threshold for IMAP connections
	icmpThreshold         = 30    // Threshold for ICMP requests
	sshThreshold          = 10    // Threshold for SSH connections
	gopherThreshold       = 5     // Threshold for Gopher connections
	detectionInterval     = 60    // Time interval (in seconds) for detecting potential attacks
	blockDuration         = 600   // Duration (in seconds) to block an IP address
	minPort               = 8080  // Minimum port to listen on (HTTP)
	maxPort               = 8081  // Maximum port to listen on (HTTP)
	httpsPort             = 8443  // Port for HTTPS
	maxConcurrentConns    = 10000 // Maximum concurrent connections to handle per port
	maxConcurrentUDPPorts = 2     // Maximum number of concurrent UDP ports to handle
)

var (
	tcpTrafficCounts     = make(map[string]int)
	udpTrafficCounts     = make(map[string]int)
	httpsTrafficCounts   = make(map[string]int)
	smtpTrafficCounts    = make(map[string]int)
	ftpTrafficCounts     = make(map[string]int)
	telnetTrafficCounts  = make(map[string]int)
	pop3TrafficCounts    = make(map[string]int)
	imapTrafficCounts    = make(map[string]int)
	icmpTrafficCounts    = make(map[string]int)
	sshTrafficCounts     = make(map[string]int)
	gopherTrafficCounts  = make(map[string]int)
	tcpTrafficCountsLock sync.Mutex
	udpTrafficCountsLock sync.Mutex
	httpsTrafficCountsLock sync.Mutex
	smtpTrafficCountsLock sync.Mutex
	ftpTrafficCountsLock  sync.Mutex
	telnetTrafficCountsLock sync.Mutex
	pop3TrafficCountsLock sync.Mutex
	imapTrafficCountsLock sync.Mutex
	icmpTrafficCountsLock sync.Mutex
	sshTrafficCountsLock sync.Mutex
	gopherTrafficCountsLock sync.Mutex
)

func blockIP(ipAddress string, protocol string) {
	// Implement IP blocking based on the protocol (e.g., using iptables or a similar tool)
	fmt.Printf("Blocked incoming %s traffic from %s\n", protocol, ipAddress)
}

func detectAndMitigateDDoS(port int, protocol string) {
	var (
		trafficCounts     map[string]int
		trafficCountsLock *sync.Mutex
		threshold         int
	)

	switch protocol {
	case "tcp":
		trafficCounts = tcpTrafficCounts
		trafficCountsLock = &tcpTrafficCountsLock
		threshold = tcpThreshold
	case "udp":
		trafficCounts = udpTrafficCounts
		trafficCountsLock = &udpTrafficCountsLock
		threshold = udpThreshold
	case "https":
		trafficCounts = httpsTrafficCounts
		trafficCountsLock = &httpsTrafficCountsLock
		threshold = httpsThreshold
	case "smtp":
		trafficCounts = smtpTrafficCounts
		trafficCountsLock = &smtpTrafficCountsLock
		threshold = smtpThreshold
	case "ftp":
		trafficCounts = ftpTrafficCounts
		trafficCountsLock = &ftpTrafficCountsLock
		threshold = ftpThreshold
	case "telnet":
		trafficCounts = telnetTrafficCounts
		trafficCountsLock = &telnetTrafficCountsLock
		threshold = telnetThreshold
	case "pop3":
		trafficCounts = pop3TrafficCounts
		trafficCountsLock = &pop3TrafficCountsLock
		threshold = pop3Threshold
	case "imap":
		trafficCounts = imapTrafficCounts
		trafficCountsLock = &imapTrafficCountsLock
		threshold = imapThreshold
	case "icmp":
		trafficCounts = icmpTrafficCounts
		trafficCountsLock = &icmpTrafficCountsLock
		threshold = icmpThreshold
	case "ssh":
		trafficCounts = sshTrafficCounts
		trafficCountsLock = &sshTrafficCountsLock
		threshold = sshThreshold
	case "gopher":
		trafficCounts = gopherTrafficCounts
		trafficCountsLock = &gopherTrafficCountsLock
		threshold = gopherThreshold
	}

	for {
		trafficCountsLock.Lock()
		for ip, count := range trafficCounts {
			// If traffic count exceeds the threshold, block the IP
			if count > threshold {
				blockIP(ip, protocol)
				delete(trafficCounts, ip)
				fmt.Printf("DDoS detected from %s on port %d (%s). Blocked for %d seconds.\n", ip, port, protocol, blockDuration)
				go unblockAfterDuration(ip, protocol, blockDuration)
			} else {
				trafficCounts[ip] = 0
			}
		}
		trafficCountsLock.Unlock()
		time.Sleep(detectionInterval * time.Second)
	}
}

func unblockAfterDuration(ipAddress string, protocol string, durationSeconds int) {
	time.Sleep(time.Duration(durationSeconds) * time.Second)
	// Implement unblocking of the IP address after the specified duration
	fmt.Printf("Unblocked incoming %s traffic from %s after %d seconds.\n", protocol, ipAddress, durationSeconds)
}

func main() {
	fmt.Printf("Monitoring ports %d-%d for potential attacks...\n", minPort, maxPort)

	// HTTP (non-HTTPS) ports
	for port := minPort; port <= maxPort; port++ {
		go listenOnPort(port, "tcp")
		go detectAndMitigateDDoS(port, "tcp")
	}

	// HTTPS port (with self-signed certificate)
	go listenOnPort(httpsPort, "https")
	go detectAndMitigateDDoS(httpsPort, "https")

	// Add a few UDP ports for monitoring
	for udpPort := 9000; udpPort < 9000+maxConcurrentUDPPorts; udpPort++ {
		go listenOnPort(udpPort, "udp")
		go detectAndMitigateDDoS(udpPort, "udp")
	}

	// Implement monitoring and mitigation for other protocols here
	select {}
}

func listenOnPort(port int, protocol string) {
	address := fmt.Sprintf(":%d", port)
	network := "tcp"

	if protocol == "udp" {
		network = "udp"
	}

	if protocol == "https" {
		httpsListener := createHTTPSListener(address)
		if httpsListener != nil {
			defer httpsListener.Close()
			http.Serve(httpsListener, nil)
		}
		return
	}

	listener, err := net.Listen(network, address)
	if err != nil {
		fmt.Printf("Error listening on port %d (%s): %v\n", port, protocol, err)
		return
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Error accepting connection on port %d (%s): %v\n", port, protocol, err)
			continue
		}

		// Check if the maximum number of concurrent connections is reached
		if protocol == "tcp" && countConnections(port, protocol) > maxConcurrentConns {
			// Simulate blocking the IP for a short duration as a mitigation measure
			remoteAddr := conn.RemoteAddr().String()
			blockIP(remoteAddr, protocol)
			fmt.Printf("Blocked incoming %s traffic from %s on port %d due to potential overload.\n", protocol, remoteAddr, port)
			go unblockAfterDuration(remoteAddr, protocol, 30) // Unblock after 30 seconds (simulated)
			conn.Close()
			continue
		}

		// Handle incoming connections and update traffic counts
		go handleConnection(conn, port, protocol)
	}
}

func handleConnection(conn net.Conn, port int, protocol string) {
	remoteAddr := conn.RemoteAddr().String()
	var (
		trafficCounts     map[string]int
		trafficCountsLock *sync.Mutex
	)

	switch protocol {
	case "tcp":
		trafficCounts = tcpTrafficCounts
		trafficCountsLock = &tcpTrafficCountsLock
	case "udp":
		trafficCounts = udpTrafficCounts
		trafficCountsLock = &udpTrafficCountsLock
	case "https":
		trafficCounts = httpsTrafficCounts
		trafficCountsLock = &httpsTrafficCountsLock
	case "smtp":
		trafficCounts = smtpTrafficCounts
		trafficCountsLock = &smtpTrafficCountsLock
	case "ftp":
		trafficCounts = ftpTrafficCounts
		trafficCountsLock = &ftpTrafficCountsLock
	case "telnet":
		trafficCounts = telnetTrafficCounts
		trafficCountsLock = &telnetTrafficCountsLock
	case "pop3":
		trafficCounts = pop3TrafficCounts
		trafficCountsLock = &pop3TrafficCountsLock
	case "imap":
		trafficCounts = imapTrafficCounts
		trafficCountsLock = &imapTrafficCountsLock
	case "icmp":
		trafficCounts = icmpTrafficCounts
		trafficCountsLock = &icmpTrafficCountsLock
	case "ssh":
		trafficCounts = sshTrafficCounts
		trafficCountsLock = &sshTrafficCountsLock
	case "gopher":
		trafficCounts = gopherTrafficCounts
		trafficCountsLock = &gopherTrafficCountsLock
	}

	trafficCountsLock.Lock()
	trafficCounts[remoteAddr]++
	trafficCountsLock.Unlock()

	// Handle the connection here (e.g., for logging or further processing)
	conn.Close()
}

func createHTTPSListener(address string) net.Listener {
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		fmt.Println("Error loading server certificate:", err)
		return nil
	}

	config := &tls.Config{Certificates: []tls.Certificate{cert}}

	httpsListener, err := tls.Listen("tcp", address, config)
	if err != nil {
		fmt.Printf("Error creating HTTPS listener on %s: %v\n", address, err)
		return nil
	}

	return httpsListener
}

func countConnections(port int, protocol string) int {
	// Implement a method to count current connections for the given port and protocol
	return 0 // Placeholder; implement as needed
}
hreshold {
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
