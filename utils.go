package main

import (
	"bufio"
	"fmt"
	"log"
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

func readToken(challenge *WatchguardResponse, token string) (string, error) {
	if token == "" {
		fmt.Println(challenge.Challenge)
		var err error
		reader := bufio.NewReader(os.Stdin)
		token, err = reader.ReadString('\n')
		if err != nil {
			return "", err
		}
	} else {
		log.Printf("got as challage: `%s`, select `%s`\n", challenge.Challenge, token)
	}

	return strings.TrimSpace(token), nil
}
