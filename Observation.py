import abc
from datetime import *
import json
import re


class Observation:

    @abc.abstractmethod
    def evaluation(self, *arg):
        pass


class StatusCode(Observation):

    def __init__(self, params):
        self.params = params

    def evaluation(self, *arg):
        """
        arg[0]: intruder_request
        arg[1]: intruder_response
        arg[2]: repeater_request
        arg[3]: repeater_response
        """
        response = arg[1]  # RESPONSE
        """results = dict()
        if len(self.params) != 0:
            for p in self.params:
                if p == response["status_code"]:
                    results.update({p: "is present"})"""

        return {"StatusCode": response["status_code"]}


class SearchKeyword(Observation):
    KEYWORD_CONFIG = 'config/keyword.json'
    FUZZ_LIST_CONFIG = 'config/fuzz_list.json'

    def __init__(self, params):
        self.params = params
        with open(self.KEYWORD_CONFIG, encoding='utf-8') as json_keyword:
            self.keyword_list = json.load(json_keyword)
        with open(self.FUZZ_LIST_CONFIG, encoding='utf-8') as json_fuzz:
            self.fuzz_list = json.load(json_fuzz)

    def prepare_keywords(self, valid_response):
        new_keyword_list = []
        for k in self.keyword_list["Keyword"]:
            result = re.search(re.escape(k), valid_response["html"], re.MULTILINE)
            if result is None:
                new_keyword_list.append(k)
        return new_keyword_list

    def evaluation(self, *arg):
        """
        arg[0]: intruder_request
        arg[1]: intruder_response
        arg[2]: repeater_request
        arg[3]: repeater_response
        """
        response = arg[1]
        intruder_request = arg[0]
        results = dict()
        #keyword_list = self.prepare_keywords(arg[3])
        keyword_list = self.keyword_list["Keyword"]
        attack_payload = self.payload_search(intruder_request)
        # CONTROLLO SE LE KEYWORD SONO RIFLESSE NELLA RISPOSTA
        results = self.keywords_search(keyword_list, response, results)
        # CONTROLLO SE I PARAMETRI SONO RIFLESSI NELLA RISPOSTA
        results = self.keywords_search(self.params, response, results)
        # CONTROLLO SE IL PAYLOAD E' RIFLESSO NELLA RISPOSTA
        if attack_payload is not None:
            results = self.keywords_search(attack_payload, response, results)
        return results

    def payload_search(self, request):
        result = []
        for f in self.fuzz_list["fuzz_list"]:
            result_url = re.search(f, request["url"])
            result_cookie = re.search(f, request["headers"]["Cookie"])
            result_post = re.search(f, request["payload request"])
            if (result_url is not None) or (result_cookie is not None) or (result_post is not None):
                result.append(f)
                break
        if len(result) == 0:
            return None
        else:
            return result

    def keywords_search(self, keyword_list, response, results):
        """
        :param keyword_list: lista di keyword su cui iterare
        :param response: http response
        :param results: dict results
        :return:
        """
        for k in keyword_list:
            match = re.search(re.escape(k), response["html"])
            if match is not None:
                results.update({"SearchKeyword_"+k: "1"})
            else:
                results.update({"SearchKeyword_"+k: "0"})
        return results


class TimeDelay(Observation):
    PERCENTAGE_TIME = 30

    def __init__(self, params):
        self.params = params

    def evaluation(self, *arg):
        """
        arg[0]: intruder_request
        arg[1]: intruder_response
        arg[2]: repeater_request
        arg[3]: repeater_response
        """
        response_time = datetime.strptime(arg[3]["time_elapsed"], "%H:%M:%S.%f").time()
        response_time_int = int(response_time.strftime("%H%M%S%f"))

        valid_time = datetime.strptime(arg[1]["time_elapsed"], "%H:%M:%S.%f").time()
        valid_time_int = int(valid_time.strftime("%H%M%S%f"))

        if response_time_int > valid_time_int + ((valid_time_int * self.PERCENTAGE_TIME)/100):
            # Revealed
            results = "1"
        else:
            # NOT Revealed
            results = "0"
        return {
            "TimeDelay": results
        }


class ContentLength(Observation):
    PERCENTAGE_LENGTH = 30

    def __init__(self, params):
        self.params = params

    def evaluation(self, *arg):
        """
           arg[0]: intruder_request
           arg[1]: intruder_response
           arg[2]: repeater_request
           arg[3]: repeater_response
        """
        valid_cl = arg[3]["content_length"]
        fuzz_cl = arg[1]["content_length"]
        if fuzz_cl > valid_cl * ((valid_cl * self.PERCENTAGE_LENGTH)/100):
            # Revealed
            results = "1"
        else:
            # NOT Revealed
            results = "0"

        return {
            "ContentLength": results
        }
