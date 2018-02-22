#!/usr/bin/env python
from flask import Flask, request, jsonify
from flask import session, redirect, url_for, escape, request, g, render_template, make_response, flash
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow

import sqlalchemy
import os

import re

import ipaddress
import datetime, time

from werkzeug.routing import BaseConverter

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' +\
                                         os.path.join(basedir, 'peers.sqlite')
db = SQLAlchemy(app)
ma = Marshmallow(app)

class RegexConverter(BaseConverter):
    def __init__(self, url_map, *items):
        super(RegexConverter, self).__init__(url_map)
        self.regex = items[0]

app.url_map.converters['regex'] = RegexConverter

# Peer database model
class Peer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=False)
    pubkey = db.Column(db.String(45), unique=True)
    date_created = db.Column(db.Integer)
    ip_address = db.Column(db.Integer)
    reg_ip_address = db.Column(db.Integer)
    is_trusted = db.Column(db.Boolean())

    def __init__(self, username, pubkey, reg_ip_address):
        self.username = username
        self.pubkey = pubkey
        self.reg_ip_address = reg_ip_address
        self.is_trusted = False
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

def StatusResponse(statuscode, msg):
    return "{\n  'status': %d,\n  'text': '%s'\n}" %(statuscode, msg)

# Generate IP from PK in /16 universe
def IDtoIP(id):
    return int(ipaddress.IPv4Address("10.42.%s.%s" %(divmod(id, 255)[0], id & 255)))

# endpoint to add new peer
@app.route("/peer", methods=["POST"])
def add_peer():
    username = request.json['username']
    pubkey = request.json['pubkey']
    reg_ip_address = int(ipaddress.IPv4Address(str(request.remote_addr)))
    new_peer = Peer(username, pubkey, reg_ip_address)

    if(not re.match('[a-zA-Z0-9+]{43}=', pubkey)):
        return StatusResponse(100, "Not a valid key")

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

# Generated config for Wireguard
@app.route("/peers/config", methods=["GET"])
def get_peer_config():
    all_peers = Peer.query.all()
    resp = make_response(render_template('wireguard_config.tpl',\
                         peers=peers_schema.dump(all_peers).data))
    resp.headers['Content-type'] = 'text/plain; charset=utf-8'
    return resp

# Show all peers as JSON response
@app.route("/peers", methods=["GET"])
def get_peer():
    all_peers = Peer.query.all()
    result = peers_schema.dump(all_peers).data
    return jsonify(result)

# endpoint to get peer detail by id
#@app.route("/peer/<id>", methods=["GET"])
#def peer_detail(id):
#    peer = Peer.query.get(id)
#    return peer_schema.jsonify(peer)

# endpoint to get peer detail by pubkey
@app.route('/peer/<regex("[a-zA-Z0-9+]{43}="):key>', methods=["GET"])
def peer_detail_pubkey(key):
    print (key)
    peer = Peer.query.filter_by(pubkey=key).first()
    return peer_schema.jsonify(peer)

# endpoint to update peer trust
@app.route("/peer/<id>", methods=["PUT"])
def peer_update(id):
    peer = Peer.query.get(id)
    is_trusted = request.json['is_trusted']
    if(not is_trusted in [0, 1]):
        return StatusResponse(102, "Not a valid value for trust")
    peer.is_trusted = is_trusted

    db.session.commit()
    return peer_schema.jsonify(peer)

if __name__ == '__main__':
    app.run(debug=True)
