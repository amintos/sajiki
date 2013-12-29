# --- USERS CONTROLLER ---
from server import view, get, request, session, redirect, access, DataObject, Guest
from data import users
from beaker.crypto.pbkdf2 import crypt



@get('/')
@view('index')
@session
def main():
    return {'hello': 'world'}

@get('/login')
@view('login')
@session
def get_login():
    if 'login' in request.params:
        error = do_login(request.session, request.params.login,  request.params.password)
        if error:
            return {'error': error}
        else:
            return redirect('/')
    else:
        return {}

@get('/logout')
def get_logout():
    if 'token' in request.session:
        print "Logout: ", request.session['user'].login
        token = request.session['token']
        if access.validate_subject(token):
            access.forget_subject(token)
        del request.session['token']
    if 'user' in request.session:
        del request.session['user']
    request.session.save()
    return redirect('/login')

def do_login(session, login, password):
    db_users = list(users.find({'login': login}))
    if db_users:
        assert len(db_users) == 1, "Multiple users named %s!" % login

        db_user = db_users[0]
        passwd_hash = db_user['password']

        if passwd_hash == crypt(password, passwd_hash):
            session['user'] = DataObject(db_user)                  # USER DATA
            session['token'] = access.create_subject(db_user).id   # ACCESS TOKEN
            session.save()
            print "Login: ", login
            return None
        else:
            return "Password incorrect!"
    else:
        return "User not found!"

