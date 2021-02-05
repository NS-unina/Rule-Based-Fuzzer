from ParserClass.FuzzElement import FuzzElement


class FuzzSession:

    __id_fuzz: str
    __fuzz_elements: list
    __number_of_observation: int

    def __init__(self, id_fuzz: str):
        self.__id_fuzz = id_fuzz
        self.__fuzz_elements = []
        self.__number_of_observation = 0

    def set_id_fuzz(self, id_fuzz: str):
        self.__id_fuzz = id_fuzz

    def get_id_fuzz(self):
        return self.__id_fuzz

    def get_fuzz_elements(self):
        return self.__fuzz_elements

    def set_fuzz_elements(self, fuzz_list: list):
        self.__fuzz_elements = fuzz_list

    def get_number_of_observation(self):
        return self.__number_of_observation

    def set_number_of_observation(self, number_of_observation:int):
        self.__number_of_observation = number_of_observation

    def push(self, fuzz_element: FuzzElement):
        self.__fuzz_elements.append(fuzz_element)
