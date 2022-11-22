package main

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// The XML response returned by the WatchGuard server
type Resp struct {
	Action      string `xml:"action"`
	LogonStatus int    `xml:"logon_status"`
	LogonId     int    `xml:"logon_id"`
	Error       string `xml:"errStr"`
	Challenge   string `xml:"chaStr"`
}

func main() {
	args := os.Args[1:]

	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: watchblob <vpn-host>")
		os.Exit(1)
	}

	host := args[0]

	username, password, err := readCredentials()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not read credentials: %v\n", err)
	}

	fmt.Printf("Requesting challenge from %s as user %s\n", host, username)
	challenge, err := triggerChallengeResponse(&host, &username, &password)
	if err != nil {
		log.Fatalf("error: %s", err)
	}

	token := ""
	switch challenge.LogonStatus {
	case 4:
		token = getToken(&challenge)
		r, err := request(templateUrl(&host, templateResponseUri(challenge.LogonId, &token)))
		if err != nil {
			log.Fatalf("error: %s", err)
		}
		fmt.Println(r)
	case 8:
		token = getToken(&challenge)
		r, err := request(templateUrl(&host, templateMfaResponseUri(challenge.LogonId, &token)))
		if err != nil {
			log.Fatalf("error: %s", err)
		}
		fmt.Println(r)
	default:
		log.Fatalf("unsupported Login Status")
	}

	fmt.Printf("Login succeeded, you may now (quickly) authenticate OpenVPN with `%s` and `%s` as your password\n", username, token)
}

func readCredentials() (string, string, error) {
	fmt.Printf("Username: ")
	reader := bufio.NewReader(os.Stdin)
	username, err := reader.ReadString('\n')
	if err != nil {
		panic(err)
	}

	fmt.Printf("Password: ")
	password, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		panic(err)
	}
	fmt.Println()

	// If an error occured, I don't care about which one it is.
	return strings.TrimSpace(username), strings.TrimSpace(string(password)), err
}

func triggerChallengeResponse(host *string, username *string, password *string) (r Resp, err error) {
	return request(templateUrl(host, templateChallengeTriggerUri(username, password)))
}

func getToken(challenge *Resp) string {
	fmt.Println(challenge.Challenge)

	reader := bufio.NewReader(os.Stdin)
	token, _ := reader.ReadString('\n')

	return strings.TrimSpace(token)
}

func request(url string) (r Resp, err error) {
	fmt.Println(url)
	resp, err := http.Get(url)
	if err != nil {
		return
	}
	var buf bytes.Buffer
	tee := io.TeeReader(resp.Body, &buf)
	decoder := xml.NewDecoder(tee)

	err = decoder.Decode(&r)
	data, _ := io.ReadAll(&buf)
	fmt.Printf("%s\n", data)
	defer resp.Body.Close()

	return
}
