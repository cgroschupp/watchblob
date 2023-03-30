package main

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/urfave/cli/v2"
)

var debug bool
var inSecure bool

type AuthDomain struct {
	Name string `xml:"name"`
}

type AuthDomains struct {
	AuthDomain []AuthDomain `xml:"auth-domain"`
}

type WatchguardResponse struct {
	Action      string      `xml:"action"`
	LogonStatus int         `xml:"logon_status"`
	LogonId     int         `xml:"logon_id"`
	AuthDomains AuthDomains `xml:"auth-domain-list"`
	Error       string      `xml:"errStr"`
	Challenge   string      `xml:"chaStr"`
}

func main() {
	app := &cli.App{
		Name:  "watchblob",
		Usage: "2-factor WatchGuard VPNs with OpenVPN ",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "username",
				Usage: "Username",
			},
			&cli.StringFlag{
				Name:  "password",
				Usage: "Password",
			},
			&cli.BoolFlag{
				Name:  "password-stdin",
				Usage: "Take the password from stdin",
			},
			&cli.StringFlag{
				Name: "token",
			},
			&cli.StringFlag{
				Name:     "host",
				Required: true,
			},
			&cli.BoolFlag{
				Name:  "debug",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "insecure",
				Value: false,
				Usage: "allow insecure ssl connection to watchguard",
			},
		},
		Action: func(cCtx *cli.Context) error {
			username := cCtx.String("username")
			password := cCtx.String("password")
			token := cCtx.String("token")
			var err error

			if username == "" {
				username, err = readUsername()
				if err != nil {
					log.Fatalf("unable to read username: %s", err)
				}
			}

			if cCtx.Bool("password-stdin") {
				contents, err := io.ReadAll(os.Stdin)
				if err != nil {
					return err
				}

				password = strings.TrimSuffix(string(contents), "\n")
				password = strings.TrimSuffix(password, "\r")
			}

			if password == "" {
				password, err = readPassword()
				if err != nil {
					log.Fatalf("unable to read password: %s", err)
				}
			}
			debug = cCtx.Bool("debug")
			inSecure = cCtx.Bool("insecure")

			run(cCtx.String("host"), username, password, token)

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
func run(host, username, password, token string) {
	log.Printf("Requesting challenge from %s as user %s\n", host, username)
	challenge, err := triggerChallengeResponse(&host, &username, &password)
	if err != nil {
		log.Fatalf("unable to perform challenge request: %s", err)
	}

	if challenge.Error != "" {
		log.Fatalf("Challenge authentication failed, with login status: %d(%s)", challenge.LogonStatus, challenge.Error)
	}

	if token == "" {
		token, err = readToken(&challenge)
		if err != nil {
			log.Fatalf("unable to read token: %s", err)
		}
	}
	var response WatchguardResponse

	switch challenge.LogonStatus {
	case 4:
		response, err = request(templateUrl(&host, templateResponseUri(challenge.LogonId, &token)))
	case 8:
		response, err = request(templateUrl(&host, templateMfaResponseUri(challenge.LogonId, &token)))
	default:
		log.Fatalf("unsupported Login Status: %d", challenge.LogonStatus)
	}

	if err != nil {
		log.Fatalf("unable to perform response request: %s", err)
	}

	if response.LogonStatus != 1 {
		log.Fatalf("response authentication failed: %v", response)
	}

	log.Printf("Login succeeded, you may now (quickly) authenticate OpenVPN with `%s` and `%s` as your password\n", username, token)
}

func triggerChallengeResponse(host *string, username *string, password *string) (r WatchguardResponse, err error) {
	return request(templateUrl(host, templateChallengeTriggerUri(username, password)))
}

func request(url string) (r WatchguardResponse, err error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: inSecure},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	tee := io.TeeReader(resp.Body, &buf)
	decoder := xml.NewDecoder(tee)

	err = decoder.Decode(&r)
	data, _ := io.ReadAll(&buf)
	if debug {
		log.Printf("Response: %s", data)
	}

	return
}
