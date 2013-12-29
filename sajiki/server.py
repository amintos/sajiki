from bottle import hook, get, static_file, TEMPLATE_PATH, Jinja2Template
from bottle import app as bottle_app
from beaker.middleware import SessionMiddleware

import data
from helpers import load_access_control, setup_request

# TEST DATA!
if __name__ == '__main__':
    #data.init_images()
    data.init_users()


# --- Load User Roles and Privileges ---

access_control = load_access_control()

# --- Configure Template Engine ---

TEMPLATE_PATH[:] = ['./templates']
Jinja2Template.settings = {'autoescape': True}

# --- Configure Session management ---

session_opts = {
    'session.type': 'file',
    'session.data_dir': './session/',
    'session.auto': True,
}

app = SessionMiddleware(bottle_app(), session_opts)

# --- Hooks ---


@hook('before_request')
def before_request():
    setup_request(access_control)

# --- CONTROLLERS ---
# Import controllers which depend on the previous setup:

from errors import *
from users import *


# --- Static file handling ---

@get('/cache/<filename:re:.*\.(jpg|png|gif|ico)>')
def thumbnails(filename):
    # TODO: Access control here?
    return static_file(filename, root='cache')

@get('/<filename:re:.*\.js>')
def javascripts(filename):
    return static_file(filename, root='static/js')

@get('/<filename:re:.*\.css>')
def stylesheets(filename):
    return static_file(filename, root='static/css')

@get('/<filename:re:.*\.(jpg|png|gif|ico)>')
def images(filename):
    return static_file(filename, root='static/img')

# --- Standalone deployment ---

if __name__ == '__main__':
    from bottle import run
    run(app=app, host='localhost', port=8080)
