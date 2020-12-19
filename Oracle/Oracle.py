import json
from pyswip import Prolog
import itertools
from Oracle.FuzzElement import FuzzElement
from Oracle.FuzzSession import FuzzSession
from Oracle.Observation import Observation
from Oracle.OracleElement import OracleElement
from Oracle.OracleSession import OracleSession
from Oracle.Query import Query
from Oracle.utils.Request import Request
from Oracle.utils.Response import Response


class Oracle:
    KNOWLEDGE_BASE = './config/knowledge_base.pl'
    RULES_CONFIG_FILE = '../config/rules_prototype.json'

    __fuzz_sessions = list
    __prolog = Prolog
    __oracle_sessions = list

    def __init__(self, observer_file_path):
        """
        :param observer_file_path: observer output file
        """
        try:
            with open(observer_file_path, encoding='utf-8') as json_request:
                self.observer_json = json.load(json_request, encoding="utf-8")
            with open(self.RULES_CONFIG_FILE, encoding='utf-8') as json_rules_prototype:
                self.rules_prototype_json = json.load(json_rules_prototype, encoding="utf-8")
        except FileNotFoundError as e:
            exit(e)

        self.__prolog = Prolog()
        self.__prolog.consult(self.KNOWLEDGE_BASE)
        self.__fuzz_sessions = list()
        self.__oracle_sessions = list()

    def execute(self):
        self.parser()
        self.build_oracle_sessions()
        for oracle_session in self.__oracle_sessions:
            oracle_session.execute()
        self.print_output()

    def print_output(self):
        print("### ORACLE RESULTS ###")
        for oracle_session in self.__oracle_sessions:
            oracle_elements_count = oracle_session.get_number_of_oracle_element()
            query_on_session_count = oracle_session.get_number_of_query_on_session()
            query_on_session_success = oracle_session.get_number_of_query_success_on_session()
            query_on_session_failed = oracle_session.get_number_of_query_failed_on_session()
            print("Number of oracle element: %s" % oracle_elements_count)
            print("Number of query on session %s" % query_on_session_count)
            print("Number of query success on session: %s" % query_on_session_success)
            print("Number of query failed on session: %s" % query_on_session_failed)

    def build_oracle_sessions(self):
        for fuzz_session in self.__fuzz_sessions:
            oracle_session = OracleSession(fuzz_session)
            for fuzz_element in fuzz_session.get_fuzz_element():
                observation_object = fuzz_element.get_observation()
                observation = observation_object.get_observation()
                query_list = self.build_query_list(observation)
                oracle_element = OracleElement(fuzz_element, query_list)
                oracle_session.push_oracle_element(oracle_element)
            self.__oracle_sessions.append(oracle_session)

    def build_query_list(self, observation: list):
        query_oracle_list = list()
        for rules in self.rules_prototype_json['prototype']:
            query_name = rules['name']
            # BUILD PROTOTYPE NAME OF RULES
            query_parameter = list(map(lambda x: '%s', rules['parameter']))
            query_parameter = ",".join(query_parameter)  # return %s,%s,%s,...
            prototype_rules = '' + query_name + '(' + query_parameter + ')'

            observation_element_primitive = list()
            observation_element_dict = list()
            for param in rules['parameter']:
                if type(observation[param]) != dict:
                    observation_element_primitive.append([{param: observation[param]}])
                else:
                    tmp_observation_element_dict = list()
                    for key in observation[param]:
                        tmp_observation_element_dict.append({param: {key: observation[param][key]}})
                    observation_element_dict.append(tmp_observation_element_dict)

            # PRODUCT CARTESIAN FOR RULES
            tuple_rules_fuzz_element = list(
                itertools.product(*observation_element_primitive, *observation_element_dict))
            # PARSING TUPLE TO DICT
            for tuple in tuple_rules_fuzz_element:
                observation_dict_query = dict()
                for value in tuple:
                    observation_dict_query.update(value)
                value_query = list()
                # GET VALUE OF OBSERVATION IN ORDER
                for param in rules['parameter']:
                    if type(observation_dict_query[param]) != dict:
                        value_query.append(observation_dict_query[param])
                    else:
                        keys = dict.keys(observation_dict_query[param])
                        key = list(keys)[0]
                        value_query.append(observation_dict_query[param][key])
                query_oracle_list.append(Query(prototype_rules, observation_dict_query, value_query))
        return query_oracle_list

    """
    parserizza il file json e mi costruisce degli oggetti
    """

    def parser(self):
        for id_fuzz in self.observer_json:
            current_fuzz = FuzzSession(id_fuzz)
            for session_request in self.observer_json[id_fuzz]['Results']:
                current_request = Request(session_request['Request']['method'], session_request['Request']['url'],
                                          session_request['Request']['headers'],
                                          session_request['Request']['payload request'])
                current_response = Response(session_request['Response']['url'],
                                            session_request['Response']['status_code'],
                                            session_request['Response']['header'],
                                            session_request['Response']['time_elapsed'],
                                            session_request['Response']['content_length'],
                                            session_request['Response']['html'])
                current_observation = Observation(session_request['Observation'])
                current_fuzz_element = FuzzElement(current_request, current_response, current_observation)
                current_fuzz.push(current_fuzz_element)
            self.__fuzz_sessions.append(current_fuzz)
