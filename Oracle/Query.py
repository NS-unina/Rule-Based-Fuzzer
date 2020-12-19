from pyswip import Prolog


class Query:
    __rules: str
    __observation: dict
    __value: list
    __result: bool
    __prolog: Prolog

    def __init__(self, rules: str, observation: dict, value: list):
        self.__rules = rules
        self.__observation = observation
        self.__value = value
        self.__prolog = Prolog()

    def get_rules(self):
        return self.__rules

    def set_rules(self, rules: str):
        self.__rules = rules

    def get_observation(self):
        return self.__observation

    def set_observation(self, observation: dict):
        self.__observation = observation

    def get_value(self):
        return self.__value

    def set_value(self, value: list):
        self.__value = value

    def get_result(self):
        return self.__result

    def execute(self):
        # TODO: DA ELIMINARE, BISOGNA CAMBIARE LA MODALITà DI RAPPRESENTAZIONE DELLE OSSERVAZIONI
        self.__value[2] = 0
        self.__value[3] = 0
        self.__result = bool(list(self.__prolog.query(self.__rules % tuple(self.__value))))
