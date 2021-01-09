from ParserClass.AnalyzerElement import AnalyzerElement


class AnalyzerSession:
    __analyzer_element: AnalyzerElement
    __id_fuzz: str

    def __init__(self, id_fuzz: str, analyzer_element: AnalyzerElement):
        """
        :param id_fuzz: id_fuzz string
        """
        self.__analyzer_element = analyzer_element
        self.__id_fuzz = id_fuzz

    def get_id_fuzz(self):
        return self.__id_fuzz

    def set_id_fuzz(self, id_fuzz: str):
        self.__id_fuzz = id_fuzz

    def get_analyzer_element(self):
        return self.__analyzer_element

    def set_repeater_element(self, analyzer_element: AnalyzerElement):
        self.__analyzer_element = analyzer_element
