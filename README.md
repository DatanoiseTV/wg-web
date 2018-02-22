# wg-web
A CRUD-Application for managing WireGuard peers (e.g. for dynamic peer management) - WiP

## Prerequisites

* Ubuntu as client distribution
* jq (apt install jq)
* wireguard package installed
* curl package installed
* Python3 installed
* pip3 install -r requirements.txt (on server side)


For the client, only curl, wireguard, jq is necessary.
Just run ```bash client/register.sh``` and follow instructions.

## URLs

### Create/add new peer:
* URL: /peer
* Method: POST
* Parameters: username, pubkey

### Return all users as JSON
* URL: /peers
* Method: GET

### Return single peer by pubkey
* URL: /peer/<pubkey>

### Return Wireguard-compliant config for all peers
* URL: /peers/config

### Trust / untrust a single peer
* URL: /peer/<pk>
* METHOD: PUT
