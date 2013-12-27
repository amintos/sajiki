# --- CONTROLLER ---
from server import view, get, post

@get('/')
@view('index')
def main():
    return {'hello': 'world'}
