

class Request:

    __method: str
    __url: str
    __headers: dict
    __payload: dict

    def __init__(self, method: str, url: str, headers: dict, payload: str) -> object:
        self.__method = method
        self.__url = url
        self.__headers = headers
        self.__payload = payload

    def get_method(self):
        return self.__method

    def set_method(self, method: str):
        self.__method = method

    def get_url(self):
        return self.__url

    def set_url(self, url: str):
        self.__url = url

    def get_headers(self):
        return self.__headers

    def set_headers(self, headers:dict):
        self.__headers = headers

    def get_payload(self):
        return self.__payload

    def set_payload(self, payload: str):
        self.__payload = payload


