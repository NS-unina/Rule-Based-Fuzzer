import ParserClass.Request as Request
import ParserClass.Response as Response


class RepeaterElement:
    __placeholder_request: Request
    __request: Request
    __response: Response

    def __init__(self, request: Request, response: Response, placeholder_request: Request):
        self.__request = request
        self.__response = response
        self.__placeholder_request = placeholder_request

    def get_request(self):
        return self.__request

    def set_request(self, request: Request):
        self.__request = request

    def get_response(self):
        return self.__response

    def set_response(self, response: Response):
        self.__response = response

    def get_placeholder_request(self):
        return self.__placeholder_request

    def set_placeholder_request(self, placeholder_request: Request):
        self.__placeholder_request = placeholder_request

