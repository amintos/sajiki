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
         ['crud', [['if-equals', 'posts', 'user_id', 'id']]],
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
        self.acd.init_role_model(test_roles)

    def test_role_update(self):
        acd = AccessControlDomain()
        acd.init_role_model(test_roles)

    def test_subject_retrieval(self):
        subj = self.acd.get_subject(test_mod)

    def test_mod_can_modify_posts(self):
        subj = self.acd.get_subject(test_mod)
        self.assertTrue(subj.can('update', 'posts'))

    def test_mod_cannot_modify_comments(self):
        subj = self.acd.get_subject(test_mod)
        self.assertFalse(subj.can('update', 'comments'))

    def test_mod_can_delete_comments(self):
        subj = self.acd.get_subject(test_mod)
        self.assertTrue(subj.can('delete', 'comments'))

    def test_user_cannot_modify_all_posts(self):
        subj = self.acd.get_subject(test_user)
        self.assertFalse(subj.can('modify', 'posts'))

    def test_user_can_modify_own_posts(self):
        subj = self.acd.get_subject(test_user)
        self.assertTrue(subj.can('update', 'posts', {'user_id': 2}))

    def test_user_cannot_modify_other_posts(self):
        subj = self.acd.get_subject(test_user)
        self.assertFalse(subj.can('update', 'posts', {'user_id': 3}))
        print subj.debug()

    def test_user_sees_users(self):
        subj = self.acd.get_subject(test_user)
        self.assertTrue(subj.can('read', 'users'))

    def test_guest_sees_no_users_but_posts_and_comments(self):
        subj = self.acd.get_subject(test_guest)
        self.assertFalse(subj.can('read', 'users'))
        self.assertTrue(subj.can('read', 'posts'))
        self.assertTrue(subj.can('read', 'comments'))


if __name__ == '__main__':
    unittest.main(exit=False)
