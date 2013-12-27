#
#   Role- and Attribute Based Access Control System
#

# TODO: Implement update for single roles
#       (This should eliminate the need for a full reload of all roles
#        if a role is updated at runtime)

from collections import defaultdict

class Subject(object):
    """Represents an active entity. Obtains permissions from roles.
       Descriptor-field can contain a dictionary with the subjects's attributes
       to support attribute-based access control"""

    def __init__(self, roles, ops_hierarchy, descriptor = None):
        self.permissions = defaultdict(lambda: [])
        self.roles = roles
        self.descriptor = descriptor or dict()

        # optimization: compute permission closures sorted by operation
        for role in self.roles:
            for permission in role.resolve(ops_hierarchy):
                self.permissions[permission.operation].append(permission)
    
    def can(self, operation, resource=None):
        """Checks whether the given operation is allowed on the resource"""
        if operation in self.permissions:
            for permission in self.permissions[operation]:
                if permission.check(self.descriptor, resource):
                    return True
        return False

    def be_admin(self):
        self.__class__ = Admin


def Admin(Subject):
    """Represents a superuser. Grants all permissions."""
    def can(self, operation, resource=None):
        return True


class Permission(object):
    """Permission to perform the said operation on a target"""

    def __init__(self, operation, target):
        self.operation = operation
        self.constraint = target

    def check(self, subject, resource):
        return self.constraint.check(subject, resource, self.operation)

    def resolve(self, hierarchy):
        """Compute the closure of the given operation (all sub-operations)"""
        if self.operation in hierarchy:
            subsets = [Permission(sub_op, self.target).resolve(hierarchy)
                        for sub_op in hierarchy[self.operations]]
            return reduce(set.union, subsets, set())        
        else:
            return { self }

    def __hash__(self):
        return hash(self.operation) ^ hash(self.constraint)

    def __eq__(self, other):
        return self.operation == other.operation and \
               self.target == other.target

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

    def check(self, subject, resource_descriptor, op):
        return self.resource == resource_descriptor if self.resource else True

    def as_dict(self):
        return self.resource if self.resource else True

       
class AttributeTarget(ResourceTarget):
    """Matches if some resource's attribute has the (constant) value"""

    def __init__(self, attribute, value):
        ResourceTarget.__init__(self, None)
        self.attribute = attribute
        self.value = value

    def check(self, subject, resource_descriptor):
        assert hasattr(resource_descriptor, '__getitem__'), \
               'Attribute-based permission check requires a dict object!'
        return self.value == resource_descriptor[self.attribute]

    def as_dict(self):
        return ['if-const', self.attribute, self.value]


class AttributeInclusionTarget(AttributeTarget):
    """Matches if the resource's attribute contains the specified value.
       This may be useful for additional simple ACLs on resource side."""

    def __init__(self, attribute, value):
        AttributeTarget.__init__(self, attribute, value)

    def check(self, subject, resource_descriptor):
        return self.value in resource_descriptor[self.attribute]

    def as_dict(self):
        return ['if-contains', self.attribute, self.value]


class AttributeEqualityTarget(AttributeTarget):
    """Matches if the resource's attribute contains the specified value.
       This may be useful for additional simple ACLs on resource side."""

    def __init__(self, resource_attr, subject_attr):
        AttributeTarget.__init__(self, resource_attr, subject_attr)

    def check(self, subject, resource_descriptor):
        assert hasattr(resource_descriptor, '__getitem__'), \
               'Attribute-based permission check requires a dict object!'
        return subject[self.value] == resource_descriptor[self.attribute]

    def as_dict(self):
        return ['if-equals', self.attribute, self.value]


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

    def check(self, subject, resource_descriptor):
        self.cls.check_method(subject, resource_descriptor, *self.args)

    def as_dict(self):
        return [self.cls.name] + list(self.args)

class Role(JointPermission):
    """A Role organizes a set of permissions. Roles inherit permissions."""
    
    def __init__(self, name, parent, permissions):
        JointPermission.__init__(self, permissions)
        self.name = name
        self.parent = parent

    def resolve(self, hierarchy):
        return JointPermission.resolve(self, hierarchy).union(
            self.parent.resolve(hierarchy) if self.parent else set())

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

        # hierarchy of operation hypernyms
        self.ops_hierarchy = DEFAULT_OPS_HIERARCHY
        
        self.special_targets = {
            'if-const': AttributeTarget,
            'if-equals': AttributeEqualityTarget,
            'if-contains': AttributeInclusionTarget,
            }

    def permission(name):
        def permission_decorator(func):
            cls = UserDefinedTargetClass(name, func)
            self.special_targets[name] = cls
            return cls
        return permission_decorator

    def parse_role(self, d_role):
        perms = [self.parse_operation(op) for op in d_role['can']]
        parent = self.roles[d_role['parent']] if 'parent' in d_role else None
        role = Role(d_role['name'], parent, perms)
        self.roles[role.name] = role

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
            result = Permission(op, self.parse_target(d_target))
            self.permissions[key] = result
            return result

    def parse_target(self, d_target):
        # cache common sub-expressions
        key = tuple(d_target) if isinstance(d_target, list) else d_target
        if key in self.targets:
            return self.targets[key]
        
        if isinstance(d_target, str):
            result = ResourceTarget(d_target)
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
        
    def update_role_model(self, d_roles):
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


    def update_operations_hierarchy(self, d_ops_hierarchy):
        self.ops_hierarchy = d_ops_hierarchy

    def get_subject(self, descriptor):
        roles = [self.roles[role_name] for role_name in descriptor['roles']]
        return Subject(roles, self.ops_hierarchy, descriptor)
        
        
        
