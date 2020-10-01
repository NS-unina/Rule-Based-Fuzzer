import abc
import json
import re


class Observation:

    @abc.abstractmethod
    def evaluation(self, data):
        pass


class StatusCode(Observation):

    def __init__(self, params):
        self.params = params

    def evaluation(self, response):
        print("STATUS EVAL")
        if len(self.params) != 0:
            for p in self.params:
                if p == response["status_code"]:
                    print("%s è presente" %p)
                else:
                    print("%s non è presente" %p)
        else:
            print("NON CI SONO PARAMETRI")


class SearchKeyword(Observation):
    KEYWORD_CONFIG = 'config/keyword.json'

    def __init__(self, params):
        self.params = params
        with open(self.KEYWORD_CONFIG, encoding='utf-8') as json_keyword:
            self.keyword_list = json.load(json_keyword)

    def evaluation(self, response):
        print("SearchKeyword eval")
        for k in self.keyword_list["Keyword"]:
            match = re.search(re.escape(k), response["html"])
            if match is not None:
                print("%s è stata trovata" %k)
            else:
                print("%s non è stata trovata" %k)


class TimeDelay(Observation):

    def __init__(self, params):
        self.params = params

    def evaluation(self, response):
        print("TimeDelay eval")
        print(self.params)
