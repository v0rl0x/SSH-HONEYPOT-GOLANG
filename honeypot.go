package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

const (
	logFile = "logins.honeypot"
)

var ports = []string{
	"222", "2222", "24442", "3389", "12222", "8008", "2200", "8080", "2022", "24", "8022", "22222", "22",
}

func logCredentials(username, password, port, clientIP string) {
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	_, err = writer.WriteString(fmt.Sprintf("%s:%s | PORT: %s | %s\n", username, password, port, clientIP))
	if err != nil {
		log.Fatalf("Failed to write to log file: %v", err)
	}
	writer.Flush()
}

func handleConnection(conn net.Conn, config *ssh.ServerConfig, port string) {
	clientIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()
	_, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}

		go func(in <-chan *ssh.Request) {
			for req := range in {
				if req.Type == "shell" {
					req.Reply(true, nil)
				} else {
					req.Reply(false, nil)
				}
			}
		}(requests)

		channel.Write([]byte("Username: "))
		username, err := bufio.NewReader(channel).ReadString('\n')
		if err != nil {
			channel.Close()
			return
		}
		username = strings.TrimSpace(username)

		channel.Write([]byte("Password: "))
		password, err := bufio.NewReader(channel).ReadString('\n')
		if err != nil {
			channel.Close()
			return
		}
		password = strings.TrimSpace(password)

		logCredentials(username, password, port, clientIP)
		channel.Write([]byte("Access denied\r\n"))
		channel.Close()
	}
}

func startServer(port string, config *ssh.ServerConfig) {
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Failed to bind to port %s: %v", port, err)
	}
	defer listener.Close()

	log.Printf("Honeypot SSH server listening on port %s", port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleConnection(conn, config, port)
	}
}

func main() {
	privateKey, err := ssh.ParsePrivateKey([]byte(`private SSH key goes here (run ssh-keygen)`))

	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			username := c.User()
			password := string(pass)
			clientIP := c.RemoteAddr().(*net.TCPAddr).IP.String()
			logCredentials(username, password, c.LocalAddr().String(), clientIP)
			return nil, fmt.Errorf("password rejected for %q", username)
		},
	}

	config.AddHostKey(privateKey)

	var wg sync.WaitGroup
	for _, port := range ports {
		wg.Add(1)
		go func(port string) {
			defer wg.Done()
			startServer(port, config)
		}(port)
	}
	wg.Wait()
}
