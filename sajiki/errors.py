from bottle import error
from helpers import view, session

@error(403)
@view('forbidden')
@session
def forbidden(error):
    return {'text': error.body}