import abc
from datetime import *
import json
import re

from ParserClass.Request import Request
from ParserClass.Response import Response


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

        return {"StatusCode": response.get_status_code()}


class SearchKeyword(Observation):
    KEYWORD_CONFIG = 'config/keyword.json'
    FUZZ_LIST_CONFIG = 'config/fuzz_list_short.json'

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

        keyword_list = self.keyword_list["Keyword"]
        attack_payload = self.payload_search(intruder_request)
        # CONTROLLO SE LE KEYWORD SONO RIFLESSE NELLA RISPOSTA
        results = self.keywords_search(keyword_list, response, results)
        # CONTROLLO SE I PARAMETRI SONO RIFLESSI NELLA RISPOSTA
        results = self.keywords_search(self.params, response, results)
        # CONTROLLO SE IL PAYLOAD E' RIFLESSO NELLA RISPOSTA
        if attack_payload is not None:
            results = self.keywords_search(attack_payload, response, results)
        return {'SearchKeyword': results}

    def payload_search(self, request: Request):
        result = []
        for f in self.fuzz_list["fuzz_list"]:
            result_url = re.search(f, request.get_url())
            request_header = request.get_header()
            result_cookie = re.search(f, request_header["Cookie"])
            result_post = re.search(f, request.get_payload())
            if (result_url is not None) or (result_cookie is not None) or (result_post is not None):
                result.append(f)
                break
        if len(result) == 0:
            return None
        else:
            return result

    def keywords_search(self, keyword_list, response: Response, results: dict):
        """
        :param keyword_list: lista di keyword su cui iterare
        :param response: http response
        :param results: dict results
        :return:
        """
        for k in keyword_list:
            match = re.search(re.escape(k), response.get_html(), re.IGNORECASE)
            if match is not None:
                results.update({k: 1})
            else:
                results.update({k: 0})

        return results


class TimeDelay(Observation):
    PERCENTAGE_TIME = 30

    def __init__(self, params):
        self.params = params

    def evaluation(self, *arg):
        """
        arg[0]: intruder_request : Request
        arg[1]: intruder_response : Response
        arg[2]: repeater_request : Request
        arg[3]: repeater_response :Response
        """
        intruder_response = arg[1]
        repeater_response = arg[3]
        repeater_response.get_time_elapsed()
        response_time = datetime.strptime(repeater_response.get_time_elapsed(), "%H:%M:%S.%f").time()
        response_time_int = int(response_time.strftime("%H%M%S%f"))

        valid_time = datetime.strptime(intruder_response.get_time_elapsed(), "%H:%M:%S.%f").time()
        valid_time_int = int(valid_time.strftime("%H%M%S%f"))

        if response_time_int > valid_time_int + ((valid_time_int * self.PERCENTAGE_TIME) / 100):
            # Revealed
            results = 1
        else:
            # NOT Revealed
            results = 0
        return {
            "TimeDelay": results
        }


class ContentLength(Observation):
    PERCENTAGE_LENGTH = 30

    def __init__(self, params):
        self.params = params

    def evaluation(self, *arg):
        """
           arg[0]: intruder_request :Request
           arg[1]: intruder_response :Response
           arg[2]: repeater_request :Request
           arg[3]: repeater_response :Response
        """
        intruder_response = arg[1]
        repeater_response = arg[3]

        valid_cl = repeater_response.get_content_length()
        fuzz_cl = intruder_response.get_content_length()
        if fuzz_cl > valid_cl * ((valid_cl * self.PERCENTAGE_LENGTH) / 100):
            # Revealed
            results = 1
        else:
            # NOT Revealed
            results = 0

        return {
            "ContentLength": results
        }
