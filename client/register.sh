#!/bin/bash

set -e

die() {
	echo "[-] Error: $1" >&2
	exit 1
}

ROGRAM="${0##*/}"
ARGS=( "$@" )
SELF="$(readlink -f "${BASH_SOURCE[0]}")"
[[ $UID == 0 ]] || exec sudo -p "[?] $PROGRAM must be run as root. Please enter the password for %u to continue: " "$SELF" "${ARGS[@]}"

read -p "[?] Please enter a username to identify you in the future: " -r USERNAME

shopt -s nocasematch
CONFIGURATION_FILE="/etc/wireguard/wireguard-web.conf"
[[ -f $CONFIGURATION_FILE ]] || continue
while read -r line; do
	[[ $line =~ ^PrivateKey\ *=\ *([a-zA-Z0-9+/]{43}=)\ *$ ]] && PRIVATE_KEY="${BASH_REMATCH[1]}" && break
done < "$CONFIGURATION_FILE"
[[ -n $PRIVATE_KEY ]] && echo "[+] Using existing private key." && break
shopt -u nocasematch

if [[ -z $PRIVATE_KEY ]]; then
	echo "[+] Generating new private key."
	PRIVATE_KEY="$(wg genkey)"
fi

SERVER_URL=https://netvm.inetgrid.net

echo "[+] Contacting Mullvad API."
RESPONSE="$(curl -H "Content-Type: application/json" -X POST -d '{"username":"$USERNAME","pubkey":"$(wg pubkey <<<"$PRIVATE_KEY")"} $SERVER_URL/peer' || die "Could not talk to Server."
[[ $RESPONSE =~ ^[0-9a-f:/.,]+$ ]] || die "$RESPONSE"
ADDRESS="$RESPONSE"
DNS="193.138.219.228"

echo "[+] Writing WriteGuard configuration files."
CONFIGURATION_FILE="/etc/wireguard/wireguard-web.conf"
umask 077
mkdir -p /etc/wireguard/
rm -f "$CONFIGURATION_FILE.tmp"
cat > "$CONFIGURATION_FILE.tmp" <<-_EOF
	[Interface]
	PrivateKey = $PRIVATE_KEY
	Address = $ADDRESS

	[Peer]
	PublicKey = fJy6mFqLtRwtRD1dy2GxuYROPIy73mmE5kxzyT3ATDw=
	Endpoint = 159.89.111.118:500
	AllowedIPs = 0.0.0.0/0, ::/0
	_EOF
	mv "$CONFIGURATION_FILE.tmp" "$CONFIGURATION_FILE"
done

echo "[+] Success. The following commands may be run for connecting to Mullvad:"
echo "  \$ wg-quick up wireguard-web"
done
