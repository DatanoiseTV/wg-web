# wg-web
A CRUD-Application for managing WireGuard peers (e.g. for dynamic peer management) - WiP

## Important info

This software is very much work-in-progress. I don't recommend any use in production,
as it might end up in data loss or worse. This is provided without any warranty.

## Prerequisites

* Ubuntu as client distribution
* jq (apt install jq)
* wireguard package installed
* curl package installed
* Python3 installed
* ```pip3 install -r requirements.txt``` (on server side)

## Server-side installation (TBD)
* Install Python3 ```apt install python3```
* Go to checkout directory
* Enter venv ```python3 -mvenv venv && source venv/bin/activate```
* Install requirements ```pip install -r requirements.txt```
* Enter ```FLASK_APP=app.py flask initdb```
* Enter ```FLASK_APP=app.py flask add_user``` and follow on screen instructions
* Run app by typing ```python3 app.py``` or ```FLASK_APP=app.py run```
* Be sure to use a reverse proxy (like nginx) for exposing to public


## Client side execution
* Install jq and curl ```apt install jq curl```
* Run client and follow steps ```bash client/register.sh```

## Registering a new user (for admin / server)
* In wg-app folder, run ```FLASK_APP=app.py flask add_user``` and follow instructions.
Afterwards this login(s) will work for the basic authentication.

In case you want to use this with cURL, the URL will be user:pass@url.

## URLs

### Create/add new peer:
* URL: /peer
* Method: POST
* Parameters: username, pubkey
* Authenticated: no

### Return all users as JSON
* URL: /peers
* Method: GET
* Authenticated: yes, basic auth

### User listing with JS UI with trust management
* URL: /peers/pretty
* Method: GET
* Authenticated: yes, basic auth

### Return single peer by pubkey
* URL: /peer/PUBKEY
* Authenticated: yes, basic auth

### Return Wireguard-compliant config for all peers
* URL: /peers/config
* Authenticated: yes, basic auth

### Trust / untrust a single peer
* URL: /peer/PUBKEY/trust
* METHOD: POST
* DATA: { "is_trusted": state} where state can be 0 or 1.
* Authenticated: yes, basic auth

### Delete a single peer
* URL: /peer/PUBKEY/delete
* METHOD: POST
* Authenticated: yes, basic auth

### Create/add new user:
* URL: /api/users
* Method: POST
* Parameters: username, password
* Authenticated: no
