from pyswip import Prolog


class Query:
    __rules: str
    __observation: dict
    __value: list
    __result: bool
    __prolog: Prolog
    __type_injection: str
    __rule_mapping: str

    def __init__(self, rules: str, observation: dict, value: list, type_injection: str, rule_mapping: str):
        self.__rules = rules
        self.__observation = observation
        self.__value = value
        self.__prolog = Prolog()
        self.__type_injection = type_injection
        self.__rule_mapping = rule_mapping

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

    def get_type_injection(self):
        return self.__type_injection

    def set_type_injection(self, type_injection: str):
        self.__type_injection = type_injection

    def get_rule_mapping(self):
        return self.__rule_mapping

    def set_rule_mapping(self, rule_mapping: str):
        self.__rule_mapping = rule_mapping

    def execute(self):
        self.__result = bool(list(self.__prolog.query(self.__rule_mapping+"(%s)" % (self.__rules % tuple(self.__value)))))
