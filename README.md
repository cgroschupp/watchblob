Watchblob - Connect to 2-factor WatchGuard VPNs with OpenVPN 
===================================

This tiny helper tool makes it possible to use WatchGuard / Firebox / <<whatever
they are actually called>> VPNs that use multi-factor authentication with OpenVPN.
It supports the Watchguard Authpoint App or SMS as multi-factor.

Rather than using OpenVPN's built-in dynamic challenge/response protocol, WatchGuard
has opted for a separate implementation negotiating credentials outside of the
OpenVPN protocol, which makes it impossible to start those connections solely by
using the `openvpn` CLI and configuration files.

What this application does has been reverse-engineered from the "WatchGuard Mobile VPN
with SSL" application on OS X.

Tazjin published a [blog post](https://www.tazj.in/en/1486830338) describing the process
and what is actually going on in this protocol.

## Installation

Make sure you have Go installed and `GOPATH` configured, then simply
`go install github.com/cgroschupp/watchblob/...`.

## Usage

Right now the usage is very simple. Make sure you have the correct OpenVPN client
config ready (this is normally supplied by the WatchGuard UI) simply run:

```sh
watchblob --host vpnserver.somedomain.org --username username --password p4ssw0rd
```

```
NAME:
   watchblob - 2-factor WatchGuard VPNs with OpenVPN

USAGE:
   watchblob [global options] command [command options] [arguments...]

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --username value
   --password value
   --token value
   --host value
   --debug           (default: false)
   --insecure        allow insecure ssl connection to watchguard (default: false)
   --help, -h        show help (default: false)
```

The server responds with a challenge which is displayed to the user, wait until you
receive the SMS code or whatever and enter it. `watchblob` then completes the
credential negotiation and you may proceed to log in with OpenVPN using your username
and *the OTP token* (**not**  your password) as credentials.
