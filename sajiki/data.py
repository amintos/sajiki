#
#   Database Operations
#

from pymongo import MongoClient
from beaker.crypto.pbkdf2 import crypt

db = MongoClient('localhost').sajiki

users = db.users
roles = db.roles
operations = db.operations
images = db.images

class DataObject(object):
    def __init__(self, record):
        self.__dict__.update(record)

    @property
    def id(self):
        return self._id

class GuestUser(DataObject):
    def __init__(self):
        self.login = 'Guest'
        self.name = 'Guest User'
        self.roles = []
Guest = GuestUser()  # Singleton :P



def init_images(base='./test-images'):
    print "Indexing images..."
    images.drop()
    import os

    for f in os.listdir(base):
        path = os.path.join(base, f)
        if os.path.isdir(path):
            init_images(path)
        elif f.endswith('.jpg'):
            index_image(path)

def index_image(imgfile):
    from PIL import Image
    from hashlib import sha1
    import os

    cachefile = './cache/%s.jpg' % sha1(imgfile).hexdigest()
    im = Image.open(imgfile)
    w, h = im.size
    im.resize((160, 160 * h / w)).save(cachefile)

    images.insert(
        {'location' : imgfile,
         'previews' : {
             'small' : cachefile
         },
         'width' : w,
         'height' : h,
         'date' : os.path.getctime(imgfile),
         'tags' : []
        }
    )





def init_users():

    users.drop()
    roles.drop()
    operations.drop()

    #
    #   Example User Database:
    #       admin/admin         -> all permissions
    #       photographer/canon  -> tag/comment/vote/veto all material
    #       student/stud        -> comment/vote/veto public material
    #       staff/staff         -> comment/vote/veto public material
    #       press/press         -> see press/public material, comment/vote/veto press-/public material
    #       anonymous/anon      -> see public material

    users.insert({
        'login': 'admin',
        'name': 'Administrator',
        'password': crypt('admin'),
        'roles': ['admin']})

    users.insert({
        'login': 'photographer',
        'name': 'Test Photographer',
        'password': crypt('canon'),
        'roles': ['photographer', 'reviewer'],
    })

    users.insert({
        'login': 'student',
        'password': crypt('stud'),
        'name': 'Test Student',
        'roles': ['reviewer'],
    })

    users.insert({
        'login': 'staff',
        'name': 'Test Staff Member',
        'password': crypt('staff'),
        'roles': ['reviewer'],
    })

    users.insert({
        'login': 'press',
        'name': 'Test Press Member',
        'password': crypt('press'),
        'roles': ['press', 'reviewer'],
    })

    users.insert({
        'login': 'anonymous',
        'name': 'Random Guest',
        'password': crypt('anon'),
        'roles': ['guest'],
    })

    roles.insert({
        'name': 'admin',
        'can': [
            ['crud', ['users', 'roles', 'photos', 'comments']]
        ]})

    roles.insert({
        'name': 'photographer',
        'can': [
            ['crud', ['photos', 'galleries']],
            ['delete', ['comments']]
        ]})

    roles.insert({
        'name': 'reviewer',
        'can': [
            ['create', ['comments', 'vetos']],
            ['read', [['if-contains', 'photos', 'tags', 'public']]],
            ['read', [['if-contains', 'galleries', 'tags', 'public']]],
            # modify only comments with user_id matching the subject's _id
            ['crud', [['if-equals', 'comments', 'user_id', '_id']]]
        ]})

    roles.insert({
        'name': 'press',
        'parent' : 'reviewer',
        'can': [
            ['read', [['if-contains', 'photos', 'tags', 'press'],
                      ['if-contains', 'galleries', 'tags', 'press']]],
    ]})

    operations.insert({
        'name': 'crud',
        'includes': ['create', 'read', 'update', 'delete']})


