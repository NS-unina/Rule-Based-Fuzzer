from ParserClass.IntruderSession import IntruderSession
from ParserClass.RepeaterSession import RepeaterSession


class AnalyzerElement:
    __repeater_session: RepeaterSession
    __intruder_session: IntruderSession

    def __init__(self, repeater_session: RepeaterSession, intruder_session: IntruderSession):
        self.__repeater_session = repeater_session
        self.__intruder_session = intruder_session

    def get_repeater_session(self):
        return self.__repeater_session

    def set_repeater_session(self, repeater_session: RepeaterSession):
        self.__repeater_session = repeater_session

    def get_intruder_session(self):
        return self.__intruder_session

    def set_intruder_session(self, intruder_session: IntruderSession):
        self.__intruder_session = intruder_session
