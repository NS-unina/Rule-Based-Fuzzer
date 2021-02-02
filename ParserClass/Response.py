class Response:
    __url: str
    __status_code: int
    __header: dict
    __time_elapsed: str
    __content_length: int
    __html: str

    def __init__(self, url: str, status_code: int, header: dict, time_elapsed: str, content_length: int, html: str):
        self.__url = url
        self.__status_code = status_code
        self.__header = header
        self.__time_elapsed = time_elapsed
        self.__content_length = content_length
        self.__html = html

    def get_url(self):
        return self.__url

    def set_url(self, url: str):
        self.__url = url

    def get_status_code(self):
        return self.__status_code

    def set_status_code(self, status_code: int):
        self.__status_code = status_code

    def get_header(self):
        return self.__header

    def set_header(self, header: dict):
        self.__header = header

    def get_time_elapsed(self):
        return self.__time_elapsed

    def set_time_elapsed(self, time_elapsed: str):
        self.__time_elapsed = time_elapsed

    def get_content_length(self):
        return self.__content_length

    def set_content_length(self, content_length: int):
        self.__content_length = content_length

    def get_html(self):
        return self.__html

    def set_html(self, html: str):
        self.__html = html

    def build_dict(self, verbose:int):
        if verbose == 1:
            return {
                "url": self.__url,
                "status_code": self.__status_code,
                "header": self.__header,
                "time_elapsed": self.__time_elapsed,
                "content_length": self.__content_length,
                "html": self.__html
            }
        else:
            return {
                "url": self.__url,
                "status_code": self.__status_code,
                "time_elapsed": self.__time_elapsed,
                "content_length": self.__content_length,
            }
