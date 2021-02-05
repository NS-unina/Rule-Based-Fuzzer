from ParserClass.Request import Request
from ParserClass.Response import Response


class IntruderElement:
    __request: Request
    __response: Response
    __type_payload: str
    __payload: str

    def __init__(self, request: Request, response: Response, payload: str, type_payload: str):
        self.__request = request
        self.__response = response
        self.__payload = payload
        self.__type_payload = type_payload

    def get_request(self):
        return self.__request

    def set_request(self, request: Request):
        self.__request = request

    def get_response(self):
        return self.__response

    def set_response(self, response: Response):
        self.__response = response

    def get_payload(self):
        return self.__payload

    def set_payload(self, payload: str):
        self.__payload = payload

    def get_type_payload(self):
        return self.__type_payload

    def set_type_payload(self, type_vulnerability: str):
        self.__type_payload = type_vulnerability
