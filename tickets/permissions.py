from rest_framework.permissions import BasePermission

class UserRolePermission(BasePermission):
    """
    Custom permission class to check if the user has a specific role.
    """

    def has_permission(self, request, view):
        # Check if the user has the required role
        required_role = getattr(view, 'required_role', None)

        if required_role:
            return request.user and request.user.role == required_role

        # If no specific role is required, allow the access
        return True
    