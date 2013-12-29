#
#   Role- and Attribute Based Access Control System
#

from collections import defaultdict
from hashlib import sha1
from json import dumps

class Subject(object):
    """Represents an active entity. Obtains permissions from roles.
       Descriptor-field can contain a dictionary with the subjects's attributes
       to support attribute-based access control"""

    def __init__(self, id, roles, ops_hierarchy, cache_id_field, descriptor=None):
        self.permissions = defaultdict(lambda: [])
        self.roles = roles
        self.descriptor = descriptor or dict()
        self.cache = set()
        self.cache_id_field = cache_id_field
        self.id = id

        # optimization: compute permission closures sorted by operation
        for role in self.roles:
            for permission in role.resolve(ops_hierarchy):
                self.permissions[permission.operation].append(permission)
    
    def can(self, operation, resource_class=None, resource_descriptor=None):
        """Checks whether the given operation is allowed on the resource"""
        cache_key = None

        try:
            if resource_descriptor:
                cache_key = (operation, resource_class, resource_descriptor[self.cache_id_field])
            else:
                cache_key = (operation, resource_class)
            if cache_key in self.cache:
                return True
        except KeyError:
            pass

        if operation in self.permissions:
            for permission in self.permissions[operation]:
                if permission.check(self.descriptor, resource_class, resource_descriptor):
                    if cache_key:
                        self.cache.add(cache_key)
                    return True
        return False

    def be_admin(self):
        self.__class__ = Admin

    def debug(self):
        """Return an exhaustive debug string with all permissions"""
        result = ''
        for operation, permissions in self.permissions.iteritems():
            result += '\n' + operation + '\n' + '-' * len(operation) + '\n'
            for perm in permissions:
                result += repr(perm) + '\n'
        return result

class Admin(Subject):
    """Represents a superuser. Grants all permissions."""
    def can(self, operation, resource_class=None, resource_descriptor=None):
        return True

class NullSubjectClass(Subject):
    """Represents an unauthorized subject"""
    def __init__(self):
        Subject.__init__(self, '', [], {}, '')

    def can(self, operation, resource_class=None, resource_descriptor=None):
        return False

    def debug(self):
        return "<Unauthorized User>"

NullSubject = NullSubjectClass()     # Singleton!

class Permission(object):
    """Permission to perform the said operation on a target"""

    def __init__(self, operation, target, role):
        self.operation = operation
        self.target = target
        self.role = role

    def check(self, subject, resource_class, resource_descriptor):
        return self.target.check(subject, resource_class, resource_descriptor, self.operation)

    def resolve(self, hierarchy):
        """Compute the closure of the given operation (all sub-operations)"""
        if self.operation in hierarchy:
            subsets = [Permission(sub_op, self.target, self.role).resolve(hierarchy)
                        for sub_op in hierarchy[self.operation]]
            return reduce(set.union, subsets, set())        
        else:
            return { self }

    def __hash__(self):
        return hash(self.operation) ^ hash(self.target)

    def __eq__(self, other):
        return self.operation == other.operation and \
               self.target == other.target

    def __repr__(self):
        return "<Permission %s on %s given by %s>" % (self.operation, self.target, self.role)
    __str__ = __repr__

class JointPermission(object):

    def __init__(self, permissions):
        self.permissions = permissions
    
    def resolve(self, hierarchy):
        """Resolve to a set of child permissions (Permissison Closure)"""
        subsets = [permission.resolve(hierarchy)
                   for permission in self.permissions]
        return reduce(set.union, subsets, set())

class ResourceTarget(object):
    """Target identified if the resource names match or are None"""

    def __init__(self, resource_name=None):
        self.resource = resource_name

    def check(self, subject, resource_class, resource_descriptor, op):
        return self.resource == resource_class if self.resource else True

    def as_dict(self):
        return self.resource if self.resource else True

    def __repr__(self):
        return "<Resource %s>" % self.resource
    __str__ = __repr__

       
class AttributeTarget(ResourceTarget):
    """Matches if some resource's attribute has the (constant) value"""

    def __init__(self, resource, attribute, value):
        ResourceTarget.__init__(self, resource)
        self.attribute = attribute
        self.value = value

    def check(self, subject, resource_class, resource_descriptor, op):
        assert hasattr(resource_descriptor, '__getitem__'), \
               'Attribute-based permission check requires a dict object!'
        ResourceTarget.check(self, subject, resource_class, resource_descriptor, op)
        return self.value == resource_descriptor[self.attribute]

    def as_dict(self):
        return ['if-const', self.attribute, self.value]

    def __repr__(self):
        return "<Resource %s where %s == '%s'>" % (self.resource, self.attribute, self.value)
    __str__ = __repr__


class AttributeInclusionTarget(AttributeTarget):
    """Matches if the resource's attribute contains the specified value.
       This may be useful for additional simple ACLs on resource side."""

    def __init__(self,  resource, attribute, value):
        AttributeTarget.__init__(self,  resource, attribute, value)

    def check(self, subject, resource_class, resource_descriptor, op):
        ResourceTarget.check(self, subject, resource_class, resource_descriptor, op)
        return self.value in resource_descriptor[self.attribute]

    def as_dict(self):
        return ['if-contains', self.attribute, self.value]

    def __repr__(self):
        return "<Resource %s where %s includes '%s'>" % (self.resource, self.attribute, self.value)
    __str__ = __repr__


class AttributeEqualityTarget(AttributeTarget):
    """Matches if the resource's attribute contains the specified value.
       This may be useful for additional simple ACLs on resource side."""

    def __init__(self, resource_class, resource_attr, subject_attr):
        AttributeTarget.__init__(self, resource_class, resource_attr, subject_attr)

    def check(self, subject, resource_class, resource_descriptor, op):
        if not hasattr(resource_descriptor, '__getitem__'):
            return False
        ResourceTarget.check(self, subject, resource_class, resource_descriptor, op)
        return subject[self.value] == resource_descriptor[self.attribute]

    def as_dict(self):
        return ['if-equals', self.attribute, self.value]

    def __repr__(self):
        return "<Resource %s where %s = %s>" % (self.resource, self.attribute, self.value)
    __str__ = __repr__


class UserDefinedTargetClass(object):
    """Allows the developer to specify additional target logic"""

    def __init__(self, name, check_method):
        self.name = name
        self.check_method = check_method

    def __call__(self, *args):
        return UserDefinedTarget(self, args)

class UserDefinedTarget(object):
    """An instance of user-defined target logic"""

    def __init__(self, cls, args):
        self.cls = cls
        self.args = args

    def check(self, subject, resource_class, resource_descriptor, op):
        self.cls.check_method(subject, resource_class, resource_descriptor, op, *self.args)

    def as_dict(self):
        return [self.cls.name] + list(self.args)

    def __repr__(self):
        return "<UserDefined %s(%s)>" % (self.cls.name, self.args)
    __str__ = __repr__

class Role(JointPermission):
    """A Role organizes a set of permissions. Roles inherit permissions."""
    
    def __init__(self, name, parent, permissions):
        JointPermission.__init__(self, permissions)
        self.name = name
        self.parent = parent

        # backward reference for displaying which permission was given by which role
        for permission in self.permissions:
            permission.role = self

    def resolve(self, hierarchy):
        return JointPermission.resolve(self, hierarchy).union(
            self.parent.resolve(hierarchy) if self.parent else set())

    def __repr__(self):
        return "<Role %s>" % self.name
    __str__ = __repr__


DEFAULT_OPS_HIERARCHY = {
    'write' : ['create', 'update', 'delete'],
    'crud' : ['read', 'write']
    }

class AccessControlDomain(object):
    """Manages permissions for a set of roles"""       

    def __init__(self):
        self.roles = {}             # unique roles
        self.targets = {}           # unique target constraints
        self.permissions = {}       # unique permissions
        self.cache_id_field = '_id' # unique resource identifier to cache permissions
        self.subject_cache = {}

        # hierarchy of operation hypernyms
        self.ops_hierarchy = DEFAULT_OPS_HIERARCHY
        
        self.special_targets = {
            'if-const': AttributeTarget,
            'if-equals': AttributeEqualityTarget,
            'if-contains': AttributeInclusionTarget,
            }

    def identify_resource_by(self, field_name):
        """Set the field by which a resource will be identified. Used for caching."""
        self.cache_id_field = field_name

    def permission(self, name):
        """Yields a decorator for user-defined permission checks"""
        def permission_decorator(func):
            cls = UserDefinedTargetClass(name, func)
            self.special_targets[name] = cls
            return cls
        return permission_decorator

    def parse_role(self, d_role):
        perms = []
        for op in d_role['can']:
            perms.extend(self.parse_operation(op))
        parent = self.roles[d_role['parent']] if 'parent' in d_role else None
        role = Role(d_role['name'], parent, perms)
        self.roles[role.name] = role
        return role

    def parse_operation(self, d_op):
        operation, d_targets = d_op
        return [self.parse_permission(operation, t)
                for t in d_targets]

    def parse_permission(self, op, d_target):
        # cache permissions
        key = (op, tuple(d_target) if isinstance(d_target, list) else d_target)
        if key in self.permissions:
            return self.permissions[key]
        else:
            result = Permission(op, self.parse_target(d_target), None)
            self.permissions[key] = result
            return result

    def parse_target(self, d_target):
        # cache common sub-expressions
        key = tuple(d_target) if isinstance(d_target, list) else d_target
        if key in self.targets:
            return self.targets[key]
        
        if isinstance(d_target, str) or isinstance(d_target, unicode):
            result = ResourceTarget(str(d_target))
        elif isinstance(d_target, bool):
            if d_target:
                result = ResourceTarget(None)
            else:
                raise ValueError("Negative permission! Leave them out.")
        elif isinstance(d_target, list):
            keyword = d_target[0]
            if keyword in self.special_targets:
                result = self.special_targets[keyword](*d_target[1:])
            else:
                raise Warning("Permission type %s not recognized" % keyword)
                result = ResourceTarget(keyword)
        else:
            raise TypeError("Don't know how to interpret %s" % d_target)
        self.targets[key] = result
        return result
        
    def init_role_model(self, d_roles):
        """(Re-)Initialize role model with a description of all roles"""
        self.roles = {}
        self.targets = {}
        self.permissions = {}
        resolved = 0
        d_roles_pending = list(d_roles) # copy (will be modified!)
        
        # multi-pass role parsing, as a role can only be parsed if its
        # parent has already been parsed ("poor man's topological sort")
        while d_roles_pending:
            for i in reversed(xrange(len(d_roles_pending))):
                d_role = d_roles_pending[i]
                if 'parent' not in d_role or d_role['parent'] in self.roles:
                        self.parse_role(d_role)
                del d_roles_pending[i]

    def update_role(self, d_role):
        """Updates or puts a new role in place. Subjects do not update automatically!"""
        new_role = self.parse_role(self, d_role)
        self.update_references_to(new_role)

    def update_references_to(self, new_role):
        for role in self.roles.itervalues():
            if role.parent.name == new_role.name:
                role.parent = new_role

    def update_operations_hierarchy(self, d_ops_hierarchy):
        """Updates the hypernyms dictionary.
        It takes the form { 'operation_hypernym': ['op1', 'op2', ...], .. }"""
        self.ops_hierarchy = d_ops_hierarchy

    def create_subject(self, descriptor):
        """Generates a subject from the description (containing a 'roles' field).
        Subjects can be seen as access tokens created at login time"""
        roles = [self.roles[role_name] for role_name in descriptor['roles']]
        id = sha1(repr(descriptor)).hexdigest()
        subject = Subject(id, roles, self.ops_hierarchy, self.cache_id_field, descriptor)
        self.subject_cache[id] = subject
        return subject
        
    def get_subject_by_id(self, subject_id):
        """Retrieve an already generated subject by its ID during a session."""
        return self.subject_cache[subject_id]

    def forget_subject(self, subject_id):
        """Delete a subject from the cache at logout."""
        del self.subject_cache[subject_id]

    def validate_subject(self, subject_id):
        """Checks whether the given subject ID is valid"""
        return subject_id in self.subject_cache
