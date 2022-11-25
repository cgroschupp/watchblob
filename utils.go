package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func readUsername() (string, error) {
	fmt.Printf("Username: ")
	reader := bufio.NewReader(os.Stdin)
	username, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(username), err
}

func readPassword() (string, error) {
	fmt.Printf("Password: ")
	password, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		return "", err
	}
	fmt.Println()

	return strings.TrimSpace(string(password)), err
}

func readToken(challenge *WatchguardResponse) (string, error) {
	fmt.Println(challenge.Challenge)

	reader := bufio.NewReader(os.Stdin)
	token, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(token), nil
}
