class Observation:

    __observation: list

    def __init__(self, observation: list):
        self.__observation = observation

    def get_observation(self):
        return self.__observation

    def set_observation(self, observation: list):
        self.__observation = observation
