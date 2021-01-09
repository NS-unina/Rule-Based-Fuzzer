from ParserClass.FuzzElement import FuzzElement


class FuzzSession:

    __id_fuzz: str
    __fuzz_elements: list

    def __init__(self, id_fuzz: str):
        self.__id_fuzz = id_fuzz
        self.__fuzz_elements = []

    def set_id_fuzz(self, id_fuzz: str):
        self.__id_fuzz = id_fuzz

    def get_id_fuzz(self):
        return self.__id_fuzz

    def get_fuzz_element(self):
        return self.__fuzz_elements

    def set_fuzz_element(self, fuzz_list: list):
        self.__fuzz_elements = fuzz_list

    def push(self, fuzz_element: FuzzElement):
        self.__fuzz_elements.append(fuzz_element)
