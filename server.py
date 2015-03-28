#!/usr/bin/env python
from flask import Flask, render_template
from subprocess import check_output, CalledProcessError
from hashlib import sha256
import re

TIMEOUT = 20
PROXY = 'socks4a://127.0.0.1:9050'
USER_AGENT = 'onionjson.net'
BLACKLIST = 'blacklist.txt'
HEADERS = {
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'none';",
    'Access-Control-Allow-Origin': '*'
}
OPTIONS = [
    '-sm', str(TIMEOUT),
    '-x', PROXY,
    '-A', USER_AGENT,
    '-H', 'x-tor2web: encrypted'
]

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/<string:onion>.onion/<path:path>')
def proxy(onion, path):
    if not re.match('^[a-z0-9]{16}$', onion):
        return '', 400

    if is_blacklisted(onion):
        return '', 451

    url = 'http://%s.onion/%s' % (onion, path)
    try:
        return get(url), 200, HEADERS
    except CalledProcessError:
        return '', 502


def get(url):
    return check_output(['curl'] + OPTIONS + ['--', url])


def is_blacklisted(onion):
    h = sha256(onion).hexdigest()
    with open(BLACKLIST) as f:
        return h in [x.strip() for x in f]


if __name__ == '__main__':
    app.run()
