import csv
import sys
from Observation import *


class ManagerObs:
    OBSERVATION_CONFIG = 'config/observation.json'
    FUZZ_LIST_CONFIG = 'config/fuzz_list.json'
    OUT_FILE_PATH = 'results/observ_results.json'
    REPEATER_CONFIG_FILE = 'results/test.json'
    CSV_OUT_PATH = "results/observation.csv"
    """
    #FS: NUMERO DI FUZZ STRING UTILIZZATE
    #RC: NUMERO DI RESPONSE CONDITION: OSSERVAZIONI FATTE SU UNA RICHIESTA HTTP
    #NK: NUMERO DI KEYWORD RICERCATE
    """

    def __init__(self, intruder_file_path):
        """
        :param config_file: config file path
        """
        try:
            with open(self.OBSERVATION_CONFIG, encoding='utf-8') as json_obs:
                self.obs_json = json.load(json_obs)
            with open(intruder_file_path, encoding='utf-8') as json_config_input:
                self.intruder_json = json.load(json_config_input)
            with open(self.FUZZ_LIST_CONFIG, encoding='utf-8') as json_fuzz:
                self.fuzz_list = json.load(json_fuzz)
            with open(self.REPEATER_CONFIG_FILE, encoding='utf-8') as json_repeater:
                self.repeater_json = json.load(json_repeater)
        except FileNotFoundError as e:
            exit(e)
        self.obs_array = []
        self.header_csv_obs = []
        self.__instantiate_adapters()


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
                self.obs_array.append(instance)
                self.header_csv_obs.append(class_name)
        except ValueError:
            print("ERROR: The \"Observation.json\" configuration file contains an unimplemented class")
            exit()

    def evaluation(self):
        for id_fuzz in self.intruder_json:
            # evaluation on response attack
            for k in self.intruder_json[id_fuzz]["Results"]:
                results = dict()
                if "ERROR" not in k["Response"]:
                    intruder_request = k["Request"]
                    intruder_response = k["Response"]
                    repeater_request = self.repeater_json[id_fuzz]["Request"]
                    repeater_response = self.repeater_json[id_fuzz]["Response"]
                    for o in self.obs_array:
                        results.update(o.evaluation(intruder_request, intruder_response, repeater_request, repeater_response))
                else:
                    results.update({"ERROR": "ERROR"})
                k.update({"Observation": results})

        #self.finalize_out(self.intruder_json)
        self.finalize_out_csv(self.intruder_json)

    def finalize_out(self, json_out):
        with open(self.OUT_FILE_PATH, 'w', encoding="utf-8") as f:
            json.dump(json_out, f, indent=4, ensure_ascii=False)
            print("### LOG EXPORTED ###")

    def finalize_out_csv(self, json_out):
        f = csv.writer(open(self.CSV_OUT_PATH, "w"))
        tmp_header = ["id_fuzz", "#", "URL", "Method"]
        row_header = tmp_header + self.header_csv_obs
        f.writerow(row_header)
        num = 1
        for id_fuzz in json_out:
            for r in json_out[id_fuzz]["Results"]:
                row_list = [id_fuzz, num, r["Request"]["url"],  r["Request"]["method"]]
                obs_value = []
                for o in r["Observation"]:
                    results_obs = r["Observation"][o]["results"]
                    string_value = ""
                    if isinstance(results_obs, dict):
                        for res in results_obs:
                            string_value = string_value + str(res) + " " + results_obs[res] + " "
                    else:
                        string_value = results_obs
                    obs_value.append(string_value)
                row_list = row_list + obs_value
                f.writerow(row_list)
                num = num + 1
        print("### CSV FILE EXPORTED ###")

