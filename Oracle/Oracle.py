import csv
import json
from pyswip import Prolog
import itertools
from ParserClass.FuzzElement import FuzzElement
from ParserClass.FuzzSession import FuzzSession
from Oracle.Observation import Observation
from ParserClass.OracleElement import OracleElement
from ParserClass.OracleSession import OracleSession
from Oracle.Query import Query
from ParserClass.Request import Request
from ParserClass.Response import Response


class Oracle:
    CONFIG_FILE = './Oracle/config/config.json'

    __fuzz_sessions: list
    __prolog: Prolog
    __oracle_sessions: list
    __oracle_file_path: str
    __oracle_file_path_csv: str

    def __init__(self, analyzer_file_path, oracle_file_path: str, oracle_file_path_csv: str):
        """
        :param analyzer_file_path: observer output file
        """
        try:
            with open(self.CONFIG_FILE, encoding='utf8') as config_file:
                self.config_file = json.load(config_file)
            with open(analyzer_file_path, encoding='utf8') as json_request:
                self.analyzer_json = json.load(json_request)
            with open(self.config_file['rules_config_path'], encoding='utf8') as json_rules_prototype:
                self.rules_prototype_json = json.load(json_rules_prototype)
        except FileNotFoundError as e:
            exit(e)
        self.__oracle_file_path = oracle_file_path
        self.__oracle_file_path_csv = oracle_file_path_csv
        self.__prolog = Prolog()
        self.__prolog.consult(self.config_file['knowledge_base_path'])
        self.__fuzz_sessions = list()
        self.__oracle_sessions = list()

    def execute(self):
        self.parser()
        self.build_oracle_sessions()
        for oracle_session in self.__oracle_sessions:
            oracle_session.execute()
        self.print_output()
        self.build_output_json()

    def print_output(self):
        file = csv.writer(open(self.__oracle_file_path_csv, "w", newline="", encoding='utf8'), delimiter=";")
        row_header = ["ID_FUZZ", "RULE ACTIVATED", "RESULTS", "NUM_FUZZ_STRING",
                      "NUM_OBSERVATION"]
        file.writerow(row_header)

        number_of_fuzz_string = 0
        for payload in self.config_file['payload_mapping']:
            with open(payload['file_name'], encoding='utf8') as payload_file:
                payload_list = json.load(payload_file)
                number_of_fuzz_string = number_of_fuzz_string + len(payload_list['fuzz_list'])

        for oracle_session in self.__oracle_sessions:
            query_success_set = set()
            query_success_label_set = set()
            fuzz_session = oracle_session.get_fuzz_session()
            oracle_elements = oracle_session.get_oracle_elements()
            for oracle_element in oracle_elements:
                query_list = oracle_element.get_query_list()
                for query in query_list:
                    if query.get_result():
                        rule = query.get_rules()
                        rule = rule.replace("%s", "")
                        rule = rule.replace(",", "")
                        rule = rule.replace("()", "")
                        if not (rule in query_success_set):
                            query_success_set.add(rule)
                            query_success_label_set.add('Anomaly %s detected' % query.get_type_injection())

            number_of_observation_on_session = fuzz_session.get_number_of_observation()
            id_fuzz = fuzz_session.get_id_fuzz()

            row_csv = [id_fuzz, ",".join(list(query_success_set)),
                       ",".join(list(query_success_label_set)),
                       number_of_fuzz_string,
                       number_of_observation_on_session]
            file.writerow(row_csv)

    def build_output_json(self):
        print("### BUILD JSON FILE ###")
        oracle_session_json = dict()
        oracle_element_json = list()
        for oracle_session in self.__oracle_sessions:
            oracle_elements = oracle_session.get_oracle_elements()
            for oracle_element in oracle_elements:
                query_list = oracle_element.get_query_list()
                query_list_json = list()
                # BUILD DICT OF QUERY
                for query in query_list:
                    if query.get_result():
                        query_list_json.append({
                            "rule": query.get_rules(),
                            "value": query.get_observation(),
                            "result": query.get_result()
                        })
                fuzz_element = oracle_element.get_fuzz_element()
                request = fuzz_element.get_request()
                response = fuzz_element.get_response()
                observation = fuzz_element.get_observation()
                # BUILD DICT OF ORACLE ELEMENT
                oracle_element_json.append({
                    "Request": request.build_dict(1),
                    "Response": response.build_dict(1),
                    "TypePayload": fuzz_element.get_type_payload(),
                    "Payload": fuzz_element.get_payload(),
                    "Observation": observation.get_observation(),
                    "Oracle": query_list_json
                })
            fuzz_session = oracle_session.get_fuzz_session()
            id_fuzz = fuzz_session.get_id_fuzz()
            # BUILD DICT OF ORACLE SESSION
            oracle_session_json.update({
                id_fuzz: {
                    "Results": oracle_element_json
                }
            })
            # reset_oracle_element
            oracle_element_json = list()
        print("### (ORACLE) WAITING FOR... ###")
        with open(self.__oracle_file_path, 'w', encoding="utf-8") as f:
            json.dump(oracle_session_json, f, indent=4, ensure_ascii=False)
            print("### LOG ORACLE CREATED ###\n")

    def build_oracle_sessions(self):
        for fuzz_session in self.__fuzz_sessions:
            oracle_session = OracleSession(fuzz_session)
            for fuzz_element in fuzz_session.get_fuzz_elements():
                observation_object = fuzz_element.get_observation()
                observation = observation_object.get_observation()
                query_list = self.build_query_list(observation, fuzz_element.get_type_payload())
                oracle_element = OracleElement(fuzz_element, query_list)
                oracle_session.push_oracle_element(oracle_element)
            self.__oracle_sessions.append(oracle_session)

    def build_query_list(self, observation: list, type_payload: str):
        query_oracle_list = list()
        for rules in self.rules_prototype_json['prototype']:
            # GET TYPE OF VULNERABILITY
            type_vulnerability_on_prototype = rules['type']
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
                # GET MAPPING RULE TYPE
                type_mapping_rule = self.rules_prototype_json['mapping_vulnerability'][type_payload]['name']

                # IF FILTER VULNERABILITY IS SET
                if type_payload:
                    if type_payload.lower() == type_vulnerability_on_prototype.lower():
                        query_oracle_list.append(
                            Query(prototype_rules, observation_dict_query, value_query, type_payload,
                                  type_mapping_rule))
                else:
                    query_oracle_list.append(
                        Query(prototype_rules, observation_dict_query, value_query, type_payload,
                              type_mapping_rule))
        return query_oracle_list

    def parser(self):
        for id_fuzz in self.analyzer_json:
            current_fuzz = FuzzSession(id_fuzz)
            for session_request in self.analyzer_json[id_fuzz]['Results']:
                current_request = Request(session_request['Request']['method'], session_request['Request']['url'],
                                          session_request['Request'].get('header'),
                                          session_request['Request']['payload'])
                current_response = Response(session_request['Response']['url'],
                                            session_request['Response']['status_code'],
                                            session_request['Response'].get('header'),
                                            session_request['Response']['time_elapsed'],
                                            session_request['Response']['content_length'],
                                            session_request['Response'].get('html'))
                current_observation = Observation(session_request['Observation'])
                payload = session_request['Payload']
                current_fuzz_element = FuzzElement(current_request, current_response, current_observation, payload,
                                                   session_request['TypePayload'])
                current_fuzz.push(current_fuzz_element)
            fuzz_elements = current_fuzz.get_fuzz_elements()
            if len(fuzz_elements) != 0:
                first_fuzz_elements = fuzz_elements[0]
                observation_object = first_fuzz_elements.get_observation()
                observation = observation_object.get_observation()
                number_of_observation = 0
                for observation_key in observation:
                    if type(observation[observation_key]) == dict:
                        number_of_observation += len(observation[observation_key])
                    else:
                        number_of_observation += 1
                current_fuzz.set_number_of_observation(number_of_observation)
            self.__fuzz_sessions.append(current_fuzz)
