import json
import sys
from Observation import *


class ManagerObs:
    OBSERVATION_CONFIG = 'config/observation.json'
    #KEYWORD_CONFIG = 'config/keyword.json'
    FUZZ_LIST_CONFIG = 'config/fuzz_list.json'
    """
    #FS: NUMERO DI FUZZ STRING UTILIZZATE
    #RC: NUMERO DI RESPONSE CONDITION: OSSERVAZIONI FATTE SU UNA RICHIESTA HTTP
    #NK: NUMERO DI KEYWORD RICERCATE
    """

    def __init__(self, config_file):
        with open(self.OBSERVATION_CONFIG, encoding='utf-8') as json_obs:
            self.obs_json = json.load(json_obs)
        with open(config_file, encoding='utf-8') as json_config_input:
            self.req_resp_json = json.load(json_config_input)
        """with open(self.KEYWORD_CONFIG, encoding='utf-8') as json_keyword:
            self.keyword_list = json.load(json_keyword)"""
        with open(self.FUZZ_LIST_CONFIG, encoding='utf-8') as json_fuzz:
            self.fuzz_list = json.load(json_fuzz)

        self.FS = len(self.fuzz_list["fuzz_list"])
        #self.NK = len(self.keyword_list["Keyword"])
        self.obs_array = []

        try:
            # I instantiate the classes present in the configuration file
            for k in self.obs_json["Observation"]["Adapter"]:
                class_name = list(k)[0]
                print(class_name)
                param = k[str(class_name)]["param"]
                class_ = getattr(sys.modules[__name__], class_name)
                instance = class_(param)
                self.obs_array.append(instance)
            print(self.obs_array)
            self.RC = len(self.obs_array)

        except ValueError:
            print("ERROR: The \"Observation.json\" configuration file contains an unimplemented class")
            print(ValueError) #DEBUG
            exit()

    def evaluation(self):
        """
        {
        ...
        Observation:
            [
                {
                <nome_obs>: <results>
                }
                ...
            ]
        }
        """
        print(self.FS)
        for r in self.req_resp_json:
            # evaluation on valid request
            valid_request_dict = r["ValidRequest"]
            valid_response = valid_request_dict[1]["Response"]
            for o in self.obs_array:
                o.evaluation(valid_response)
            # evaluation on response attack
            for k in r["Results"]:
                for o in self.obs_array:
                    print(k["Response"])
                    o.evaluation(k["Response"])