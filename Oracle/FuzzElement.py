import Oracle.Observation as Observation
import Oracle.utils.Request as Request
import Oracle.utils.Response as Response


class FuzzElement:
    __request: Request
    __response: Response
    __observation: Observation

    def __init__(self, request: Request, response: Response, observation: Observation):
        self.__request = request
        self.__response = response
        self.__observation = observation

    def get_request(self):
        return self.__request

    def set_request(self, request: Request):
        self.__request = request

    def get_response(self):
        return self.__response

    def set_response(self, response: Response):
        self.__response = response

    def get_observation(self):
        return self.__observation

    def set_observation(self, observation: Observation):
        self.__observation = observation
