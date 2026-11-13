"""Vehicle telemetry upload service (fixture with planted defects)."""
import hashlib
import os
import pickle
import sqlite3
import subprocess
import sys

import yaml
from flask import Flask, request

from app import config

app = Flask(__name__)


def get_db():
    return sqlite3.connect("telemetry.db")


@app.route("/vehicle")
def vehicle():
    vin = request.args.get("vin", "")
    cur = get_db().cursor()
    # planted: SQL injection
    cur.execute("SELECT * FROM vehicles WHERE vin = '%s'" % vin)
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # planted: command injection
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/calc")
def calc():
    # planted: arbitrary code execution
    return str(eval(request.args.get("expr", "0")))


@app.route("/config", methods=["POST"])
def load_config():
    # planted: unsafe YAML load and unsafe deserialisation
    data = yaml.load(request.data)
    session = pickle.loads(request.files["session"].read())
    return str((data, session))


def fingerprint(payload, cache={}):
    # planted: weak hash, mutable default argument
    digest = hashlib.md5(payload).hexdigest()
    cache[digest] = payload
    return digest


def export(path):
    try:
        with open(path) as fh:
            return fh.read()
    except:
        pass
    # planted: undefined name
    return default_payload


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=config.DEBUG)
