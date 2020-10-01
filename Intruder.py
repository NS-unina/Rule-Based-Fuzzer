import json
import re
import copy
from requests import Request, Session
from hyper.contrib import HTTP20Adapter
from Utils import Utils


class Intruder:
    FUZZ_LIST_CONFIG = 'config/fuzz_list.json'
    #OBSERVATION_CONFIG = 'config/observation.json'
    #KEYWORD_CONFIG = 'config/keyword.json'
    OUT_FILE_PATH = 'results/results.json'

    def __init__(self, file_name_path="results/test.json"):
        with open(file_name_path, encoding='utf-8') as json_request:
            self.request_json = json.load(json_request)
        with open(self.FUZZ_LIST_CONFIG, encoding='utf-8') as json_fuzz:
            self.fuzz_list = json.load(json_fuzz)
        """with open(self.OBSERVATION_CONFIG, encoding='utf-8') as json_obs:
            self.observation_list = json.load(json_obs)"""
        """with open(self.KEYWORD_CONFIG, encoding='utf-8') as json_keyword:
            self.keyword_list = json.load(json_keyword)"""
        self.s = Session()
        self.s.mount("https://", HTTP20Adapter())

    def __scan_placeholders(self, pattern, string):
        """
        :param pattern: regex pattern
        :param string: string on which to apply the pattern
        :return: result array
        """
        return re.finditer(pattern, string)

    def __scan_parameters(self, in_array, out_array, type_param) -> []:
        """
        :param in_array: array di match ottenuti dai placeholder
        :param out_array: array di output
        :param type_param: tipologia di parametri scansionati
        :return:
        """
        for k in in_array:
            # Creo un insieme di coppie (match, type)
            out_array.append((k, type_param))
        return out_array

    # setta l'array di parametri da passare a build_config
    def __get_placeholder_param(self, request):
        """
        :param request: valid request Json
        :return: array of
        """
        # REGEX FUNCTION
        url_param = self.__scan_placeholders('([\$][^ \ & | ^ \;]+[\$])', request["PlaceholderRequest"]["Request"]["url"])
        cookie_param = self.__scan_placeholders('([\$][^ \ & | ^ \;]+[\$])', request["PlaceholderRequest"]["Request"]["headers"]["Cookie"])
        payload_req = self.__scan_placeholders('([\$][^ \ & | ^ \;]+[\$])', request["PlaceholderRequest"]["Request"]["payload request"])

        # SETTO I PARAMETRI CHE SERVIRANNO A BUILD_CONFIG
        params = []
        self.__scan_parameters(url_param, params, "Url")
        self.__scan_parameters(cookie_param, params, "Cookie")
        self.__scan_parameters(payload_req, params, "Post")
        return params

    def run_intruder(self):
        json_out_file = []
        i = 1
        for r in self.request_json:
            req_res_dict = []
            params = self.__get_placeholder_param(r)

            url = r["PlaceholderRequest"]["Request"]["url"]
            cookie = r["PlaceholderRequest"]["Request"]["headers"]["Cookie"]
            payload_req = r["PlaceholderRequest"]["Request"]["payload request"]
            print("### %s° RUN SNIPER ATTACK ###" % i)
            self.build_config(r, params, url, cookie, payload_req, req_res_dict)
            json_out_file.append({"ValidRequest": r["ValidRequest"], "Results": req_res_dict})
            i = i+1
        self.finalize_out(json_out_file)

    def build_config(self, request, params_placeholder, url, cookie, payload_req, req_res_dict):
        number = 0
        total_len = len(self.fuzz_list["fuzz_list"]) * len(params_placeholder)
        Utils.print_progress_bar(0, total_len, prefix='Progress:', suffix='Complete', length=50)
        for match, type_m in params_placeholder:
            tmp_url = url
            tmp_cookie = cookie
            tmp_payload_req = payload_req
            Utils.print_progress_bar(number + 1, total_len, prefix='Progress:', suffix='Complete', length=50)
            for fuzz_string in self.fuzz_list["fuzz_list"]:
                span = match.span()
                if type_m == "Url":
                    tmp_url = fuzz_string.join([url[:span[0]], url[span[1]:]])
                if type_m == "Cookie":
                    tmp_cookie = fuzz_string.join([cookie[:span[0]], cookie[span[1]:]])
                if type_m == "Post":
                    tmp_payload_req = fuzz_string.join([payload_req[:span[0]], payload_req[span[1]:]])
                number = number + 1

                # Elimino dalle stringhe i caratteri dei placeholder
                clear_url = self.clear_param(tmp_url, '$', '')
                clear_cookie = self.clear_param(tmp_cookie, '$', '')
                clear_payload_req = self.clear_param(tmp_payload_req, '$', '')

                # COSTRUISCO I DICT DI RICHIESTA E RISPOSTA
                tmp_dict = self.build_output_file(request, clear_url, clear_cookie, clear_payload_req, number)
                req_res_dict.append({"Request": tmp_dict[0], "Response": tmp_dict[1]})
                Utils.print_progress_bar(number, total_len, prefix='Progress:', suffix='Complete', length=50)

    def build_output_file(self, request, url, cookie, payload_req, number):
        request_dict = copy.deepcopy(request["PlaceholderRequest"]["Request"])
        request_dict["number"] = number
        request_dict["url"] = url
        request_dict["headers"]["Cookie"] = cookie
        request_dict["payload request"] = payload_req
        try:
            response = self.send_request(request_dict["method"], request_dict["url"], request_dict["headers"])
            response_dict = dict()
            response_dict["number"] = number
            response_dict["url"] = response.request.url
            response_dict["status_code"] = response.status_code
            response_dict["header"] = Utils.convert_utf8(response.headers)
            response_dict["time_elapsed"] = str(response.elapsed)
            response_dict["html"] = response.text
        except:
            response_dict = {"ERROR": "ERROR"}

        return [request_dict, response_dict]

    def clear_param(self, param, placeholder_separator, replace_string):
        return param.replace(placeholder_separator, replace_string)

    def send_request(self, method, url, headers):
        req = Request(method=method, url=url, headers=headers)
        prepped = self.s.prepare_request(req)
        response = self.s.send(prepped, timeout=5)
        return response

    def finalize_out(self, json_dict):
        with open(self.OUT_FILE_PATH, 'w', encoding="utf-8") as f:
            json.dump(json_dict, f, indent=4, ensure_ascii=False)
            print("### LOG EXPORTED ###")
