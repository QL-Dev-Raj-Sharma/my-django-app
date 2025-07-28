from .constants import Constant
from django.http import JsonResponse
from rest_framework.response import Response
from my_project.exceptions import ApiException


class Responder:

    @staticmethod
    def send(code, data=None, status=True):
        return Response(
            {
                "status": status,
                "code": code,
                "message": Constant.response_messages[code],
                "data": data if data is not None else {},
            },
            status=200 if status else 400
        )

    @staticmethod
    def raise_error(code):
        raise ApiException(code)

    @staticmethod
    def send_json(code, data=None, status=True):
        return JsonResponse(
            {
                "status": status,
                "code": code,
                "message": Constant.response_messages[code],
                "data": data if data is not None else {},
            },
            status=200 if status else 400
        )
