#!/bin/bash
#
# Copyright (C) 2016-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
#
# This file is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#
# This file is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this file. If not, see <http://www.gnu.org/licenses/>.

set -e

die() {
	echo "[-] Error: $1" >&2
	exit 1
}

ROGRAM="${0##*/}"
ARGS=( "$@" )
SELF="$(readlink -f "${BASH_SOURCE[0]}")"

dist=`grep DISTRIB_ID /etc/*-release | awk -F '=' '{print $2}'`
if [ "$dist" != "Ubuntu" ]; then
  echo "Only Ubuntu is currently supported, sorry."
  exit 1
fi

[[ $UID == 0 ]] || exec sudo -p "[?] $PROGRAM must be run as root. Please enter the password for %u to continue: " "$SELF" "${ARGS[@]}"

dec2ip () {
    local ip dec=$@
    for e in {3..0}
    do
        ((octet = dec / (256 ** e) ))
        ((dec -= octet * 256 ** e))
        ip+=$delim$octet
        delim=.
    done
    printf '%s\n' "$ip"
}

read -p "[?] Please enter a username to identify you in the future: " -r USERNAME

shopt -s nocasematch
CONFIGURATION_FILE="/etc/wireguard/wireguard-web.conf"

if [[ -f $CONFIGURATION_FILE ]]; then
  while read -r line; do
  	[[ $line =~ ^PrivateKey\ *=\ *([a-zA-Z0-9+/]{43}=)\ *$ ]] && PRIVATE_KEY="${BASH_REMATCH[1]}" && break
  done < "$CONFIGURATION_FILE"
fi

[[ -n $PRIVATE_KEY ]] && echo "[+] Using existing private key."
shopt -u nocasematch

if [[ -z $PRIVATE_KEY ]]; then
	echo "[+] Generating new private key."
	PRIVATE_KEY="$(wg genkey)"
fi

SERVER_URL=https://netvm.inetgrid.net

echo "[+] Contacting Server API."
PUBLIC_KEY=$(wg pubkey <<<"$PRIVATE_KEY")
RESPONSE=$(curl -s -H "Content-Type: application/json" -X POST -d '{"username":"'$USERNAME'","pubkey":"'$PUBLIC_KEY'"}' $SERVER_URL/peer | jq '.ip_address')
[[ $RESPONSE =~ ^[0-9a-f:/.,]+$ ]] || die "$RESPONSE"
ADDRESS="$(dec2ip $RESPONSE)"
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

echo "[+] Success. The following commands may be run for connecting:"
echo "  \$ wg-quick up wireguard-web"
