from bottle import app, hook, get, static_file, request, redirect
from bottle import TEMPLATE_PATH
from bottle import jinja2_view
from beaker.middleware import SessionMiddleware
from access import AccessControlDomain
import data
from data import Guest, DataObject

from users import *

#data.init_images()

# Set up Role-Based Access Control

data.init_users()

access = AccessControlDomain()
access.update_operations_hierarchy(list(data.operations.find()))
access.init_role_model(list(data.roles.find()))

# Template Engine

TEMPLATE_PATH.append('./templates')                     # Lookup path

def view(name):
    return jinja2_view('%s.jinja2' % name)

def session(func):
    """Decorator which adds a bunch of session parameters to a handler's response.
    Only applicable to view-decorated handlers!"""
    def session_wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        result.update({'user': request.session['user']})
        result.update({'logged_in': 'token' in request.session})
        return result
    return session_wrapper

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
    if not 'user' in request.session:
        request.session['user'] = Guest


print "[RBAC] Derived %s permissions from %s roles" % (
    len(access.permissions), len(access.roles))

# Request handlers (Controllers)


# Static files

@get('/<filename:re:.*\.js>')
def javascripts(filename):
    return static_file(filename, root='static/js')

@get('/<filename:re:.*\.css>')
def stylesheets(filename):
    return static_file(filename, root='static/css')

@get('/<filename:re:.*\.(jpg|png|gif|ico)>')
def images(filename):
    return static_file(filename, root='static/img')

# Standalone config

if __name__ == '__main__':
    from bottle import run
    run(app=app, host='localhost', port=8080)
