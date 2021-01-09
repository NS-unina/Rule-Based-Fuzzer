from ParserClass.FuzzElement import FuzzElement


class OracleElement:
    __fuzz_element: FuzzElement
    __query_list: list
    # STATISTICS VARIABLE
    __number_of_query: int
    __number_of_query_success: int
    __number_of_query_failed: int

    def __init__(self, fuzz_element: FuzzElement, query_list: list):
        self.fuzz_element = fuzz_element
        self.query_list = query_list
        self.__number_of_query = 0
        self.__number_of_query_success = 0
        self.__number_of_query_failed = 0

    def get_fuzz_element(self):
        return self.fuzz_element

    def set_fuzz_element(self, fuzz_element: FuzzElement):
        self.fuzz_element = fuzz_element

    def get_query_list(self):
        return self.query_list

    def set_query_list(self, query_list: list):
        self.query_list = query_list

    def get_number_of_query(self):
        return self.__number_of_query

    def get_number_of_query_success(self):
        return self.__number_of_query_success

    def get_number_of_query_failed(self):
        return self.__number_of_query_failed

    def execute(self):
        for query in self.query_list:
            query.execute()
            query_results = query.get_result()
            self.__number_of_query += 1
            if query_results is True:
                self.__number_of_query_success += 1
            else:
                self.__number_of_query_failed += 1
