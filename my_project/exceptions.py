from django.core.exceptions import PermissionDenied


class ApiException(Exception):

    def __init__(self, error_code):
        self.error_code = error_code