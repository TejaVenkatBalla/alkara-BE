"""
Decorators
"""
from functools import wraps

def validate_mandatory_fields(required_fields):
    """
    This function validates the mandatory fields.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(request_data):
            for field in required_fields:
                if field not in request_data:
                    raise ValueError(f"Mandatory field '{field}' is missing in the request data")
            return func(request_data)
        return wrapper
    return decorator
