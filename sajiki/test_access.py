from access import AccessControlDomain
import unittest

# resources in question:
#   blog posts, comments

test_mod = {
    'id': 1,
    'login': 'mod',
    'password': '***',
    'roles' : ['moderator']
    }

test_user = {
    'id': 2,
    'login': 'user',
    'password': '****',
    'roles' : ['publisher', 'community_member'] 
    }

test_guest = {
    'id': 3,
    'login': 'guest',
    'password': '*****',
    'roles' : ['guest']
    }


test_roles= [
    {'name' : 'moderator',
     'parent' : 'publisher',
     'can' : [
         ['crud', ['posts']],
         ['delete', ['comments']]
         ]
     },
    {'name' : 'publisher',
     'parent' : 'guest',
     'can' : [
         ['crud', [['if-equals', 'user_id', 'id']]],
         ['read', ['comments', 'posts']]
         ]
     },
    {'name' : 'community_member',
     'can' : [
         ['read', ['users']]
        ]
     },
    {'name':  'guest',
     'can' : [
         ['read', ['comments', 'posts']]
         ]
     }
    ]

class AccessControlTest(unittest.TestCase):

    def setUp(self):
        self.acd = AccessControlDomain()
        self.acd.update_role_model(test_roles)

    def test_role_update(self):
        acd = AccessControlDomain()
        acd.update_role_model(test_roles)

    def test_subject_retrieval(self):
        print self.acd.roles
        subj = self.acd.get_subject(test_mod)

if __name__ == '__main__':
    unittest.main(exit=False)
