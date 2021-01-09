class Request:
    __method: str
    __url: str
    __header: dict
    __payload: dict

    def __init__(self, method: str, url: str, header: dict, payload: str) -> object:
        self.__method = method
        self.__url = url
        self.__headers = header
        self.__payload = payload

    def get_method(self):
        return self.__method

    def set_method(self, method: str):
        self.__method = method

    def get_url(self):
        return self.__url

    def set_url(self, url: str):
        self.__url = url

    def get_header(self):
        return self.__headers

    def set_header(self, header: dict):
        self.__header = header

    def get_payload(self):
        return self.__payload

    def set_payload(self, payload: str):
        self.__payload = payload

    def build_dict(self):
        return {
            "method": self.__method,
            "url": self.__url,
            "header": self.__headers,
            "payload": self.__payload
        }
