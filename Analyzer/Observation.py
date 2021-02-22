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
        arg[4]: payload
        """
        response = arg[1]
        intruder_request = arg[0]
        results = dict()

        keyword_list = self.keyword_list["Keyword"]
        # CONTROLLO SE LE KEYWORD SONO RIFLESSE NELLA RISPOSTA
        results = self.keywords_search(keyword_list, response, results)
        # CONTROLLO SE IL PAYLOAD E' RIFLESSO NELLA RISPOSTA
        if arg[4] is not None:
            results = self.keywords_search([arg[4]], response, results)
        return {'SearchKeyword': results}

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
    PERCENTAGE_TIME = 200

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
        repeater_response_time = datetime.strptime(repeater_response.get_time_elapsed(), "%H:%M:%S.%f").time()
        repeater_response_time_int = int(repeater_response_time.strftime("%H%M%S%f"))

        intruder_response_time = datetime.strptime(intruder_response.get_time_elapsed(), "%H:%M:%S.%f").time()
        intruder_response_time_int = int(intruder_response_time.strftime("%H%M%S%f"))

        if intruder_response_time_int > repeater_response_time_int + (
                (repeater_response_time_int * self.PERCENTAGE_TIME) / 100):
            # Revealed
            results = 1
        else:
            # NOT Revealed
            results = 0
        return {
            "TimeDelay": results
        }


class ContentLength(Observation):
    PERCENTAGE_LENGTH = 500

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
        if fuzz_cl > valid_cl + ((valid_cl * self.PERCENTAGE_LENGTH) / 100):
            # Revealed
            results = 1
        else:
            # NOT Revealed
            results = 0

        return {
            "ContentLength": results
        }
