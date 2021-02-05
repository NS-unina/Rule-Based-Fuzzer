from ParserClass.FuzzSession import FuzzSession
from ParserClass.OracleElement import OracleElement


class OracleSession:
    __fuzz_session: FuzzSession
    __oracle_elements: list
    # STATISTICS VARIABLE
    __number_of_oracle_element: int
    __number_of_query_on_session: int
    __number_of_query_success_on_session: int
    __number_of_query_failed_on_session: int

    __number_of_anomaly_found: int
    __number_of_fuzz_string: int

    def __init__(self, fuzz_session: FuzzSession):
        self.__fuzz_session = fuzz_session
        self.__oracle_elements = list()
        self.__number_of_oracle_element = 0
        self.__number_of_query_failed_on_session = 0
        self.__number_of_query_success_on_session = 0
        self.__number_of_query_on_session = 0

    def get_fuzz_session(self):
        return self.__fuzz_session

    def set_fuzz_session(self, fuzz_session: FuzzSession):
        self.__fuzz_session = fuzz_session

    def get_oracle_elements(self):
        return self.__oracle_elements

    def set_oracle_elements(self, oracle_elements: list):
        self.__oracle_elements = oracle_elements

    def get_number_of_oracle_element(self):
        return self.__number_of_oracle_element

    def get_number_of_query_on_session(self):
        return self.__number_of_query_on_session

    def get_number_of_query_success_on_session(self):
        return self.__number_of_query_success_on_session

    def get_number_of_query_failed_on_session(self):
        return self.__number_of_query_failed_on_session

    def push_oracle_element(self, oracle_element: OracleElement):
        self.__oracle_elements.append(oracle_element)

    def execute(self):
        for oracle_element in self.__oracle_elements:
            oracle_element.execute()
            self.__number_of_oracle_element += 1
            self.__number_of_query_on_session += oracle_element.get_number_of_query()
            self.__number_of_query_success_on_session += oracle_element.get_number_of_query_success()
            self.__number_of_query_failed_on_session += oracle_element.get_number_of_query_failed()
