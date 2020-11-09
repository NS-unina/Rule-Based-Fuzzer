import json
import re
import copy

import requests
from requests import Request, Session
from Utils import Utils

"""
TODO:RISOLVERE IL PROBLEMA DEL TIMEOUT QUANDO HO RICHIESTE TIMEDELAY
TODO: BUG parametri post con lo spazio non vengono identificati 
"""

class Intruder:
    FUZZ_LIST_CONFIG = 'config/fuzz_list.json'
    #OUT_FILE_PATH = 'results/intruder.json'
    TIMEOUT_VALUE = 30 #SECOND

    def __init__(self, repeater_file_path, out_file_path):
        """
        :param file_name_path: repeater configuration file
        """
        try:
            with open(repeater_file_path, encoding='utf-8') as json_request:
                self.repeater_json = json.load(json_request, encoding="utf-8")
            with open(self.FUZZ_LIST_CONFIG, encoding='utf-8') as json_fuzz:
                self.fuzz_list = json.load(json_fuzz, encoding="utf-8")
        except FileNotFoundError as e:
            exit(e)
        self.out_file_path = out_file_path
        self.s = Session()

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

    # setta l'array di parametri da passare a build_config
    def __get_placeholder_param(self, request):
        """
        :param request: valid request Json
        :return: array of
        """
        params = []
        # REGEX FUNCTION
        url_param = self.__scan_placeholders('([\$][^ \ & | ^ \;]+[\$])', request["PlaceholderRequest"]["url"])
        if 'Cookie' in dict(request["PlaceholderRequest"]["headers"]):
            cookie_param = self.__scan_placeholders('([\$][^ \ & | ^ \;]+[\$])', request["PlaceholderRequest"]["headers"]["Cookie"])
        else:
            cookie_param = ""
        payload_req = self.__scan_placeholders('([\$][^\§|]+[\$]|\$\$)', request["PlaceholderRequest"]["payload request"])

        # SETTO I PARAMETRI CHE SERVIRANNO A BUILD_CONFIG
        self.__scan_parameters(url_param, params, "Url")
        self.__scan_parameters(cookie_param, params, "Cookie")
        self.__scan_parameters(payload_req, params, "Post")
        return params

    def run_intruder(self):
        json_out_file = dict()
        i = 1
        for id_fuzz in self.repeater_json:
            req_res_dict = []
            params = self.__get_placeholder_param(self.repeater_json[id_fuzz])
            url = self.repeater_json[id_fuzz]["PlaceholderRequest"]["url"]
            if 'Cookie' in dict(self.repeater_json[id_fuzz]["PlaceholderRequest"]["headers"]):
                cookie = self.repeater_json[id_fuzz]["PlaceholderRequest"]["headers"]["Cookie"]
            else:
                cookie = ""
            payload_req = self.repeater_json[id_fuzz]["PlaceholderRequest"]["payload request"]
            print("### %s° RUN SNIPER ATTACK ###" % i)
            self.build_config(self.repeater_json[id_fuzz], params, url, cookie, payload_req, req_res_dict)
            out_tmp = {
                id_fuzz: {
                    "Results": req_res_dict
                }
            }
            json_out_file.update(out_tmp)
            i = i+1
        self.finalize_out(json_out_file)

    def build_config(self, request, params_placeholder, url, cookie, payload_req, req_res_dict):
        number = 0
        total_len = len(self.fuzz_list["fuzz_list"]) * len(params_placeholder)
        if total_len == 0:
            print("# REQUEST SKIPPED ###")
        else:
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
                tmp_dict = self.build_output_file(request, clear_url, clear_cookie, clear_payload_req)
                req_res_dict.append({"Request": tmp_dict[0], "Response": tmp_dict[1]})
                Utils.print_progress_bar(number, total_len, prefix='Progress:', suffix='Complete', length=50)

    def build_output_file(self, request, url, cookie, payload_req):
        request_dict = copy.deepcopy(request["PlaceholderRequest"])
        request_dict["url"] = url
        request_dict["headers"]["Cookie"] = cookie
        request_dict["payload request"] = payload_req
        try:
            response = self.send_request(request_dict["method"], request_dict["url"].encode(), request_dict["headers"], payload_req)
            response_dict = {
                "url": response.request.url,
                "status_code": response.status_code,
                "header": dict(response.headers), # QUI DA IL PROBLEMA DEI BYTE
                "time_elapsed": str(response.elapsed),
                "content_length": len(response.content),
                "html": response.text
            }
        except requests.exceptions.RequestException as e:
            response_dict = {"ERROR": str(e)}

        return [request_dict, response_dict]

    def clear_param(self, param, placeholder_separator, replace_string):
        return param.replace(placeholder_separator, replace_string)

    def send_request(self, method, url, headers, payload):
        payload_dict = dict()
        if len(payload) != 0:
            data = payload.split("§")
            for d in data:
                tmp = d.split("=")
                payload_dict.update({tmp[0]: tmp[1]})
        req = Request(method=method, url=url, headers=headers, data=payload_dict)
        prepped = self.s.prepare_request(req)
        response = self.s.send(prepped, timeout=self.TIMEOUT_VALUE)

        return response

    def finalize_out(self, json_dict):
        with open(self.out_file_path, 'w', encoding="utf-8") as f:
            json.dump(json_dict, f, indent=4, ensure_ascii=False)
            print("### LOG EXPORTED ###")
