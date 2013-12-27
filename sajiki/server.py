from bottle import app, hook, get, post, redirect, request
from bottle import TEMPLATE_PATH
from bottle import jinja2_view
from beaker.middleware import SessionMiddleware

# Template Engine

TEMPLATE_PATH.append('./templates')                     # Lookup path
view = lambda name: jinja2_view('%s.jinja2' % name)     # Template file suffix

# Session Engine (= WSGI middleware)

session_opts = {
    'session.type': 'file',
    'session.data_dir': './session/',
    'session.auto': True,
}

app = SessionMiddleware(app(), session_opts)

# Hooks
# -> inject session variable into request

@hook('before_request')
def setup_request():
    request.session = request.environ['beaker.session']

# Request handlers (Controllers)

from users import *


# Standalone config

if __name__ == '__main__':
    from bottle import run
    run(app=app, host='localhost', port=8080)
