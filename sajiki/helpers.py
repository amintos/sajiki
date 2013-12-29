#
#   Helpers/Decorators
#

from bottle import jinja2_view, request, HTTPError
from access import AccessControlDomain, NullSubject
import data
from data import Guest, users, DataObject
from beaker.crypto.pbkdf2 import crypt

# --- REQUEST HANDLING  ---


def view(name):
    """Decorator around handlers rendering the given view"""
    return jinja2_view('%s.jinja2' % name)


def session(func):
    """Decorator which adds a bunch of session parameters to a handler's response.
    Only applicable to view-decorated handlers!"""
    def session_wrapper(*args, **kwargs):
        result = func(*args, **kwargs)

        # Additional parameters sent to the template renderer:
        result.update({'user': request.session['user'],
                       'subject': request.subject,
                       'logged_in': 'token' in request.session})
        return result
    return session_wrapper


# Convenience method for access rights check:
def can(action, resource_class=None, resource_desc=None):
    """Checks whether the logged in user can perform 'action' on the resource"""
    if not request.subject.can(action, resource_class, resource_desc):
        raise HTTPError(403, "This action requires '%s' privilege on '%s'" % (action, resource_class))

# --- SETUP  ---


def load_access_control():
    """Load Access Control from Database"""
    access = AccessControlDomain()
    ops = {}
    for operation in data.operations.find():
        ops[operation['name']] = operation['includes']
    access.update_operations_hierarchy(ops)
    access.init_role_model(list(data.roles.find()))
    return access


def setup_request(access_control):
    """Enrich current request with user and access control data"""
    request.session = session = request.environ['beaker.session']
    request.access_control = access_control

    if not 'user' in session:
        session['user'] = Guest

    if 'token' in session:
        token = session['token']
        if access_control.validate_subject(token):
            request.subject = access_control.get_subject_by_id(token)
        else:
            request.subject = NullSubject
    else:
        request.subject = NullSubject


# --- LOGIN & LOGOUT ---

def do_login(access_control, session, login, password):
    """Login user, establish privileges in session"""
    db_users = list(users.find({'login': login}))
    if db_users:
        assert len(db_users) == 1, "Multiple users named %s!" % login

        db_user = db_users[0]
        passwd_hash = db_user['password']

        if passwd_hash == crypt(password, passwd_hash):
            session['user'] = DataObject(db_user)                  # USER DATA
            session['token'] = access_control.create_subject(db_user).id   # ACCESS TOKEN
            session.save()
            print "Login: ", login
            return None
        else:
            return "Password incorrect!"
    else:
        return "User not found!"


def do_logout(access_control, session):
    """Logout user, retract privileges from session"""
    if 'token' in session:
        token = session['token']
        if access_control.validate_subject(token):
            access_control.forget_subject(token)
        del session['token']

    if 'user' in request.session:
        print "Logout: ", session['user'].login
        del session['user']
    session.save()