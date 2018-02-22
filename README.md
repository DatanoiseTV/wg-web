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
* pip3 install -r requirements.txt (on server side)

## Server-side installation (TBD)
* Install Python3 (apt install python3)
* Go to checkout directory
* Enter venv (python3 -mvenv venv && source venv/bin/activate)
* Install requirements (pip install -r requirements.txt)
* Enter interactive shell (FLASK_APP=app.py flask shell)
* Enter ```from app import db; db.create_all()```
* Exit interactive shell with Ctrl+D
* Run app by typing ```python3 app.py``` or ```FLASK_APP=app.py run```
* Be sure to use a reverse proxy (like nginx) for exposing to public


## Client side execution
* Install jq and curl (apt install jq curl)
* Run client and follow steps ```bash client/register.sh```

## URLs

### Create/add new peer:
* URL: /peer
* Method: POST
* Parameters: username, pubkey

### Return all users as JSON
* URL: /peers
* Method: GET

### User listing with JS UI with trust management
* URL: /peers/pretty
* Method: GET

### Return single peer by pubkey
* URL: /peer/<pubkey>

### Return Wireguard-compliant config for all peers
* URL: /peers/config

### Trust / untrust a single peer
* URL: /peer/PUBKEY/trust
* METHOD: POST
* DATA: { "is_trusted": state} where state can be 0 or 1.

### Delete a single peer
* URL: /peer/PUBKEY/delete
* METHOD: POST
