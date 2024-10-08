package main

import (
	"fmt"
	"net/url"
	"strconv"
)

const urlFormat string = "https://%s%s"
const uriFormat = "/?%s"

func templateChallengeTriggerUri(username *string, password *string) string {
	v := url.Values{}
	v.Set("action", "sslvpn_logon")
	v.Set("style", "fw_logon_progress.xsl")
	v.Set("fw_logon_type", "logon")
	v.Set("fw_domain", "Firebox-DB")
	v.Set("fw_username", *username)
	v.Set("fw_password", *password)

	return fmt.Sprintf(uriFormat, v.Encode())
}

func templateResponseUri(logonId int, token *string) string {
	v := url.Values{}
	v.Set("action", "sslvpn_logon")
	v.Set("style", "fw_logon_progress.xsl")
	v.Set("fw_logon_type", "response")
	v.Set("fw_logon_id", strconv.Itoa(logonId))
	v.Set("response", *token)

	return fmt.Sprintf(uriFormat, v.Encode())
}

func templateMfaResponseUri(logonId int, choice *string) string {
	v := url.Values{}
	v.Set("action", "sslvpn_logon")
	v.Set("style", "fw_logon_progress.xsl")
	v.Set("fw_logon_type", "mfa_response")
	v.Set("fw_logon_id", strconv.Itoa(logonId))
	v.Set("mfa_choice", *choice)

	return fmt.Sprintf(uriFormat, v.Encode())
}

func templateUrl(baseUrl *string, uri string) string {
	return fmt.Sprintf(urlFormat, *baseUrl, uri)
}
