from ParserClass.RepeaterElement import RepeaterElement


class RepeaterSession:
    __repeater_element: RepeaterElement
    __id_fuzz: str

    def __init__(self, repeater_element: RepeaterElement, id_fuzz: str):
        self.__repeater_element = repeater_element
        self.__id_fuzz = id_fuzz

    def get_id_fuzz(self):
        return self.__id_fuzz

    def set_id_fuzz(self, id_fuzz: str):
        self.__id_fuzz = id_fuzz

    def get_repeater_element(self):
        return self.__repeater_element

    def set_repeater_element(self, repeater_element: RepeaterElement):
        self.__repeater_element = repeater_element
