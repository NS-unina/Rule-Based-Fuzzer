from ParserClass.IntruderElement import IntruderElement


class IntruderSession:
    __intruder_elements: list

    def __init__(self):
        self.__intruder_elements = list()

    def get_intruder_elements(self):
        return self.__intruder_elements

    def set_intruder_elements(self, intruder_elements: list):
        self.__intruder_elements = intruder_elements

    def push(self, intruder_element: IntruderElement):
        self.__intruder_elements.append(intruder_element)
