#!/usr/bin/env python
import os, sys, re

from flask import Flask, request, jsonify, session, redirect, abort,\
                  url_for, escape, request, g, render_template, make_response, flash

from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow

from flask_httpauth import HTTPBasicAuth

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import sqlalchemy

import ipaddress
import datetime, time
from passlib.hash import argon2


app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app.url_map.strict_slashes = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' +\
                                         os.path.join(basedir, 'peers.sqlite')

###### USER SETTINGS ######
app.config['API_SERVER_URL'] = 'https://netvm.inetgrid.net'
app.config['WIREGUARD_SERVER_IP'] = '159.89.111.118'
app.config['WIREGUARD_SERVER_PORT'] = 500
app.config['WIREGUARD_SERVER_PUBKEY'] = 'fJy6mFqLtRwtRD1dy2GxuYROPIy73mmE5kxzyT3ATDw='

db = SQLAlchemy(app)
ma = Marshmallow(app)
auth = HTTPBasicAuth()

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["1440 per day", "60 per hour"]
)

# For complex routes with regex
from werkzeug.routing import BaseConverter
class RegexConverter(BaseConverter):
    def __init__(self, url_map, *items):
        super(RegexConverter, self).__init__(url_map)
        self.regex = items[0]
app.url_map.converters['regex'] = RegexConverter

######## Database models and schemas ########
# User database model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True)

    allowed_num_peers = db.Column(db.Integer())
    is_active = db.Column(db.Boolean, default=False)

    # PBKDF2 with Salt with SHA256 via hashlib
    hash = db.Column(db.String(100), unique=False)

    def hash_password(self, password):
        self.hash = argon2.hash(password)

    def verify_password(self, password):
        return argon2.verify(password, self.hash)

@auth.verify_password
def verify_password(username, password):
    # first try to authenticate by token
    user = User.query.filter_by(username=username).first()
    if not user or not user.verify_password(password):
        return False
    if not user.is_active:
        return False
    g.user = user
    return True

# Peer database model
class Peer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=False)
    pubkey = db.Column(db.String(45), unique=True)
    date_created = db.Column(db.Integer)
    ip_address = db.Column(db.Integer)
    reg_ip_address = db.Column(db.Integer)
    is_trusted = db.Column(db.Boolean())

    created_by = db.Column(db.String(80))

    def __init__(self, username, pubkey, reg_ip_address, created_by):
        self.username = username
        self.pubkey = pubkey
        self.reg_ip_address = reg_ip_address
        self.is_trusted = False
        self.created_by = created_by
        self.date_created = int(time.mktime(datetime.datetime.now().timetuple()))

# Peer schema for Marshmallow
class PeerSchema(ma.ModelSchema):
    class Meta:
        model = Peer
        fields = ( 'username', 'pubkey', 'ip_address',\
                   'reg_ip_address', 'is_trusted', 'date_created'\
                 )

peer_schema = PeerSchema()
peers_schema = PeerSchema(many=True)

######## Flask CLI functions ########

# Run flask add_user to add user interactively from CLI.
@app.cli.command()
def add_user():
    username = input("Username: ")
    if(not re.match("^[a-zA-Z0-9_]+$", username)):
        print("Sorry, invalid username (only alphanumeric characters")
        sys.exit(1)
    password = input("Password: ")
    if username is None or password is None:
        print("Sorry, empty username or password.")
        sys.exit(1)
    if User.query.filter_by(username = username).first() is not None:
        print("Sorry, this user already exists.")
        sys.exit(1)
    num_peers = input("How many peers can this user add?: ")
    user = User(username = username)
    user.allowed_num_peers = int(num_peers)
    user.is_active = True
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    print("Thanks, successfully added '%s' to users." %(username))
    sys.exit(0)

######## Helper functions ########
def StatusResponse(statuscode, msg):
    return "{\n  'status': %d,\n  'text': '%s'\n}" %(statuscode, msg)

# Generate IP from PK in /16 universe
def IDtoIP(id):
    return int(ipaddress.IPv4Address("10.42.%s.%s" %(divmod(id, 255)[0], id & 255)))

# TBD (limit num peers per user)
def AllowedToAddPeer(username):
    return True

######## Routes for Peer CRUD API ########
# endpoint to add new peer
@app.route("/peer", methods=["POST"])
@auth.login_required
@limiter.limit("30 per hour")
def add_peer():
    username = request.json['username']
    pubkey = request.json['pubkey']
    reg_ip_address = int(ipaddress.IPv4Address(str(request.remote_addr)))
    created_by = auth.username()
    new_peer = Peer(username, pubkey, reg_ip_address, created_by)

    if(not re.match("[a-zA-Z0-9+/]{43}=", pubkey)):
        return StatusResponse(100, "Not a valid key")

    if(not re.match("^[a-zA-Z0-9_]+$", username)):
        return StatusResponse(100, "Not a valid username (only alphanumeric characters)")

    AllowedToAddPeer(created_by)

    try:
        db.session.add(new_peer)
        db.session.commit()
    except sqlalchemy.exc.IntegrityError:
        print("Duplicate key")
        return StatusResponse(101, "Duplicate key")

    # Refresh object after creating to fetch PK
    db.session.flush()
    new_peer.ip_address = IDtoIP(int(new_peer.id))
    db.session.commit()

    return peer_schema.jsonify(new_peer)

# Add peer using keygen in browser
@app.route("/peer/keygen", methods=["GET"])
def add_peer_keygen():
    resp = make_response(render_template('peer_keygen.html'))
    resp.headers['Content-type'] = 'text/html; charset=utf-8'
    return resp

# Generated config for Wireguard
@app.route("/peers/config", methods=["GET"])
@auth.login_required
def get_peer_config():
    all_peers = Peer.query.all()
    resp = make_response(render_template('wireguard_config.tpl',\
                         peers=peers_schema.dump(all_peers).data))
    resp.headers['Content-type'] = 'text/plain; charset=utf-8'
    return resp

# Show all peers of logged in user as JSON response
@app.route("/peers", methods=["GET"])
@auth.login_required
def get_peer():
    all_peers = Peer.query.filter_by(created_by=auth.username())
    result = peers_schema.dump(all_peers).data
    return jsonify(result)

# Show all peers pretty
@app.route("/peers/pretty", methods=["GET"])
@auth.login_required
def get_peer_pretty():
    all_peers = Peer.query.filter_by(created_by=auth.username())
    resp = make_response(render_template('peers_pretty.html',\
                         peers=peers_schema.dump(all_peers).data))
    resp.headers['Content-type'] = 'text/html; charset=utf-8'
    return resp

# endpoint to get peer detail by pubkey
@app.route('/peer/<regex("[a-zA-Z0-9+/]{43}="):key>', methods=["GET"])
@auth.login_required
def peer_detail_pubkey(key):
    print (key)
    peer = Peer.query.filter_by(pubkey=key, created_by=auth.username()).first_or_404()
    return peer_schema.jsonify(peer)

# endpoint to update peer trust
@app.route('/peer/<regex("[a-zA-Z0-9+/]{43}="):key>/trust', methods=["POST"])
@auth.login_required
def peer_update(key):
    peer = Peer.query.filter_by(pubkey=key, created_by=auth.username()).first_or_404()
    is_trusted = request.json['is_trusted']
    if(not is_trusted in [0, 1]):
        return StatusResponse(102, "Not a valid value for trust")
    peer.is_trusted = is_trusted

    db.session.commit()
    return peer_schema.jsonify(peer)

# endpoint to update peer trust
@app.route('/peer/<regex("[a-zA-Z0-9+/]{43}="):key>/delete', methods=["POST"])
@auth.login_required
def peer_delete(key):
    peer = Peer.query.filter_by(pubkey=key, created_by=auth.username()).first_or_404()
    db.session.delete(peer)
    db.session.commit()
    return peer_schema.jsonify(peer)

######## Routes for User handling ########

# Creates an user which is inactive until activated
@app.route('/api/users', methods=['POST'])
def user_register():
    username = request.json.get('username')
    password = request.json.get('password')

    if(not re.match("^[a-zA-Z0-9_]+$", username)):
        return StatusResponse(100, "Not a valid username (only alphanumeric characters)")

    if username is None or password is None:
        abort(400)
    if User.query.filter_by(username = username).first() is not None:
        abort(400)
    user = User(username = username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({ 'username': user.username }) #, 201, {'Location': url_for('get_user', id = user.id, _external = True)}


if __name__ == '__main__':
    app.run(debug=True)
