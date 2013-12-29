# --- USERS CONTROLLER ---
from bottle import get, request, redirect
from helpers import view, session, can, do_login, do_logout
import data

@get('/')
@view('index')
@session
def index():
    return {'hello': 'world'}


@get('/restricted')
def restricted():
    can('update', 'users')


@get('/login')
@view('login')
@session
def login():
    if 'login' in request.params:
        error = do_login(request.access_control,
                         request.session,
                         request.params.login,  request.params.password)
        if error:
            return {'error': error}
        else:
            return redirect('/')
    else:
        return {}


@get('/logout')
def logout():
    do_logout(request.access_control, request.session)
    return redirect('/login')


@get('/profile')
@view('profile')
@session
def profile():
    return {'debug': request.subject.debug()}



@get('/users')
@view('users')
@session
def index_users():
    return {'users': data.users.find() }