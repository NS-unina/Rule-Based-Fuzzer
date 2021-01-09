from ParserClass.Request import Request
from ParserClass.Response import Response


class IntruderElement:
    __request: Request
    __response: Response

    def __init__(self, request: Request, response: Response):
        self.__request = request
        self.__response = response

    def get_request(self):
        return self.__request

    def set_request(self, request: Request):
        self.__request = request

    def get_response(self):
        return self.__response

    def set_response(self, response: Response):
        self.__response = response
