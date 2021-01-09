import csv
import sys
from Analyzer.Observation import *
from ParserClass.AnalyzerElement import AnalyzerElement
from ParserClass.AnalyzerSession import AnalyzerSession

from ParserClass.IntruderElement import IntruderElement
from ParserClass.IntruderSession import IntruderSession
from ParserClass.RepeaterElement import RepeaterElement
from ParserClass.RepeaterSession import RepeaterSession
from ParserClass.Request import Request
from ParserClass.Response import Response


class Analyzer:
    OBSERVATION_CONFIG = 'config/observation.json'
    FUZZ_LIST_CONFIG = 'config/fuzz_list_short.json'
    OUT_FILE_PATH = '../results/observer.json'
    REPEATER_CONFIG_FILE = './results/repeater.json'
    CSV_OUT_PATH = "../results/observer.csv"

    __observation_array = list()
    __header_csv_obs = list()
    __intruder_json = list()
    __repeater_json = list()
    __analyzer_session = list()

    def __init__(self, intruder_file_path: str):
        """
        :param intruder_file_path: config file path
        """
        try:
            with open(self.OBSERVATION_CONFIG, encoding='utf-8') as json_obs:
                self.obs_json = json.load(json_obs)
            with open(intruder_file_path, encoding='utf-8') as json_config_input:
                self.__intruder_json = json.load(json_config_input)
            with open(self.FUZZ_LIST_CONFIG, encoding='utf-8') as json_fuzz:
                self.fuzz_list = json.load(json_fuzz)
            with open(self.REPEATER_CONFIG_FILE, encoding='utf-8') as json_repeater:
                self.__repeater_json = json.load(json_repeater)
        except FileNotFoundError as e:
            exit(e)
        self.__observation_array = list()
        self.__header_csv_obs = list()

        self.__analyzer_session = list()
        self.__parser()
        self.__instantiate_adapters()

    def __parser(self):
        for id_fuzz in self.__intruder_json:
            # BUILD A REPEATER SESSION
            repeater_element = self.__build_repeater_element(self.__repeater_json[id_fuzz])
            repeater_session = RepeaterSession(repeater_element, id_fuzz)
            # BUILD A INTRUDER SESSION
            intruder_session = IntruderSession()
            for intruder_request_json in self.__intruder_json[id_fuzz]["Results"]:
                if "ERROR" not in intruder_request_json["Response"]:
                    intruder_element = self.__build_intruder_element(intruder_request_json)
                    intruder_session.push(intruder_element)
            # BUILD ANALYZER ELEMENT
            analyzer_element = AnalyzerElement(repeater_session, intruder_session)
            analyzer_session = AnalyzerSession(id_fuzz, analyzer_element)
            self.__analyzer_session.append(analyzer_session)

    def __build_intruder_element(self, intruder_request_json: dict):
        intruder_request = Request(intruder_request_json['Request']['method'],
                                   intruder_request_json['Request']['url'],
                                   intruder_request_json['Request']['header'],
                                   intruder_request_json['Request']['payload'])

        intruder_response = Response(intruder_request_json['Response']['url'],
                                     intruder_request_json['Response']['status_code'],
                                     intruder_request_json['Response']['header'],
                                     intruder_request_json['Response']['time_elapsed'],
                                     intruder_request_json['Response']['content_length'],
                                     intruder_request_json['Response']['html'])
        return IntruderElement(intruder_request, intruder_response)

    def __build_repeater_element(self, repeater_json: dict):
        repeater_request = Request(repeater_json["Request"]['method'],
                                   repeater_json["Request"]['url'],
                                   repeater_json["Request"]['header'],
                                   repeater_json["Request"]['payload'])
        repeater_response = Response(repeater_json["Response"]['url'],
                                     repeater_json["Response"]['status_code'],
                                     repeater_json["Response"]['header'],
                                     repeater_json["Response"]['time_elapsed'],
                                     repeater_json["Response"]['content_length'],
                                     repeater_json["Response"]['html'])
        return RepeaterElement(repeater_request, repeater_response, None)

    def __instantiate_adapters(self):
        """
        Instantiate the observation classes
        """
        try:
            # I instantiate the classes present in the configuration file
            for k in self.obs_json["Observation"]["Adapter"]:
                class_name = list(k)[0]
                param = k[str(class_name)]["param"]
                class_ = getattr(sys.modules[__name__], class_name)
                instance = class_(param)
                self.__observation_array.append(instance)
                self.__header_csv_obs.append(class_name)
        except ValueError:
            print("ERROR: The \"Observation.json\" configuration file contains an unimplemented class")
            exit()

    def evaluation(self, csv_out_path: str, json_out_path: str):
        """
        :param csv_out_path: csv output file path
        :param json_out_path: json output file path
        """
        analyzer_json = {}
        for analyzer_session in self.__analyzer_session:
            analyzer_element = analyzer_session.get_analyzer_element()
            intruder_session = analyzer_element.get_intruder_session()
            repeater_session = analyzer_element.get_repeater_session()
            repeater_element = repeater_session.get_repeater_element()
            intruder_dict = []
            for intruder_element in intruder_session.get_intruder_elements():
                results_observation = dict()
                intruder_request = intruder_element.get_request()
                intruder_response = intruder_element.get_response()
                repeater_request = repeater_element.get_request()
                repeater_response = repeater_element.get_response()
                for o in self.__observation_array:
                    results_observation.update(
                        o.evaluation(intruder_request, intruder_response, repeater_request, repeater_response))

                current_dict = {
                    'Request': intruder_request.build_dict(),
                    'Response': intruder_response.build_dict(),
                    "Observation": results_observation
                }
                intruder_dict.append(current_dict)

            id_fuzz = analyzer_session.get_id_fuzz()
            analyzer_json.update({
                id_fuzz: {
                    "Results": intruder_dict
                }
            })

        self.finalize_out(analyzer_json, json_out_path)
        self.finalize_out_csv(analyzer_json, csv_out_path)

    @staticmethod
    def finalize_out(analyzer_json: dict, csv_out_path: str):
        with open(csv_out_path, 'w', encoding="utf-8") as f:
            json.dump(analyzer_json, f, indent=4, ensure_ascii=False)
            print("### LOG JSON EXPORTED ###")

    @staticmethod
    def finalize_out_csv(analyzer_json: dict, csv_out_path: str):
        f = csv.writer(open(csv_out_path, "w", newline="", encoding='utf8'))
        row_header = ["id_fuzz", "#", 'Payload', "URL", "Method"]
        first_iter = False
        num = 1
        row_matrix = []
        for id_fuzz in analyzer_json:
            for r in analyzer_json[id_fuzz]["Results"]:
                row_list = [id_fuzz, num, r['Request']['payload'], r["Request"]["url"], r["Request"]["method"]]
                obs_value = []
                for k, v in r["Observation"].items():
                    if first_iter is False:
                        row_header.append(k)
                    obs_value.append(v)
                # FLAG UTILE PER CREARE UNA SOLA VOLTA L'HEADER ROW
                first_iter = True
                row_list = row_list + obs_value
                row_matrix.append(row_list)
                num = num + 1
        f.writerow(row_header)
        for r in row_matrix:
            f.writerow(r)
        print("### CSV FILE EXPORTED ###")
