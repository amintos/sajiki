#
#   Database Operations
#

from pymongo import MongoClient
from beaker.crypto.pbkdf2 import crypt

db = MongoClient('localhost').sajiki

users = db.users
roles = db.roles
tags = db.tags

def init_db():
    users.insert({
        'login': 'admin',
        'password': crypt('admin')
        'roles' : ['admin']
        })

    
    roles.insert({
        'name': 'admin',
        'deny': ['*']
