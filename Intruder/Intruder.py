import json
import re
import copy
from typing import List

import requests
from requests import Request, Session

from ParserClass.RepeaterElement import RepeaterElement
from ParserClass.Request import Request as GenericRequest
from ParserClass.Response import Response as GenericResponse
from ParserClass.RepeaterSession import RepeaterSession
from Utils import Utils


class Intruder:
    CONFIG_FILE_PATH = './Intruder/config/config.json'
    TIMEOUT_VALUE = 30  # SECOND

    __config_json: dict
    __repeater_json: dict
    __fuzz_list: dict
    __repeater_sessions: List[RepeaterSession]

    def __init__(self, repeater_file_path: str, out_file_path: str):
        try:
            with open(repeater_file_path, encoding='utf-8') as json_request:
                self.__repeater_json = json.load(json_request, encoding="utf-8")

            with open(self.CONFIG_FILE_PATH, encoding='utf-8') as json_config:
                self.__config_json = json.load(json_config, encoding="utf-8")

            with open(self.__config_json['fuzz_list_config'], encoding='utf-8') as json_fuzz:
                self.__fuzz_list = json.load(json_fuzz, encoding="utf-8")

        except FileNotFoundError as e:
            exit(e)
        self.out_file_path = out_file_path
        self.s = Session()
        self.__repeater_sessions = list()
        self.parser()

    def parser(self):
        for id_fuzz in self.__repeater_json:
            request_json = self.__repeater_json[id_fuzz]['Request']
            response_json = self.__repeater_json[id_fuzz]['Response']
            placeholder_request_json = self.__repeater_json[id_fuzz]['PlaceholderRequest']
            type_vulnerability = self.__repeater_json[id_fuzz]['TypeVulnerability']
            request = GenericRequest(request_json['method'], request_json['url'], request_json['header'],
                                     request_json['payload'])
            response = GenericResponse(response_json['url'], response_json['status_code'], response_json['header'],
                                       response_json['time_elapsed'], response_json['content_length'],
                                       response_json['html'])
            placeholder_request = GenericRequest(placeholder_request_json['method'], placeholder_request_json['url'],
                                                 placeholder_request_json['header'],
                                                 placeholder_request_json['payload'])
            repeater_element = RepeaterElement(request, response, placeholder_request, type_vulnerability)
            repeater_session = RepeaterSession(repeater_element, id_fuzz)
            self.__repeater_sessions.append(repeater_session)

    def __scan_placeholders(self, pattern: str, string: str):
        """
        :param pattern: regex pattern
        :param string: string on which to apply the pattern
        :return: result array
        """
        return re.finditer(pattern, string)

    def __scan_parameters(self, in_array, out_array, type_param):
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
    def __get_placeholder_param(self, request: GenericRequest):
        params = []
        url_param = self.__scan_placeholders('([\$][^ \ & | ^ \;]+[\$])', request.get_url())
        request_header = request.get_header()
        if 'Cookie' in request_header:
            cookie_param = self.__scan_placeholders('([\$][^ \ & | ^ \;]+[\$])', request_header["Cookie"])
        else:
            cookie_param = ""
        payload_req = self.__scan_placeholders('([\$][^\§|]+[\$]|\$\$)', request.get_payload())

        # SETTO I PARAMETRI CHE SERVIRANNO A BUILD_CONFIG
        self.__scan_parameters(url_param, params, "Url")
        self.__scan_parameters(cookie_param, params, "Cookie")
        self.__scan_parameters(payload_req, params, "Post")
        return params

    def execute(self):
        output_json_dict = dict()
        i = 1
        for repeater_session in self.__repeater_sessions:
            results = []
            repeater_element = repeater_session.get_repeater_element()
            placeholder_request = repeater_element.get_placeholder_request()
            params = self.__get_placeholder_param(repeater_element.get_placeholder_request())
            print("### %s° RUN SNIPER ATTACK ###" % i)
            placeholder_header = placeholder_request.get_header()
            if 'Cookie' in placeholder_header:
                cookie = placeholder_header['Cookie']
            else:
                cookie = ""
            self.build_config(repeater_element, params, placeholder_request.get_url(),
                              cookie, placeholder_request.get_payload(), results)
            id_fuzz = repeater_session.get_id_fuzz()
            output_json_dict.update({
                id_fuzz: {
                    "Results": results
                }
            })
            i = i + 1
        self.finalize_out(output_json_dict)

    def build_config(self, request: RepeaterElement, params: list, url: str, cookie: str, payload_req: str,
                     results: list):
        number = 0
        total_len = len(self.__fuzz_list["fuzz_list"]) * len(params)
        if total_len == 0:
            print("# REQUEST SKIPPED ###")
        else:
            Utils.print_progress_bar(0, total=total_len, prefix='Progress:', suffix='Complete', length=50)

        for match, type_m in params:
            tmp_url = url
            tmp_cookie = cookie
            tmp_payload_req = payload_req
            Utils.print_progress_bar(number + 1, total_len, prefix='Progress:', suffix='Complete', length=50)
            for fuzz_string in self.__fuzz_list["fuzz_list"]:
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
                results.append({"Request": tmp_dict[0], "Response": tmp_dict[1],
                                "TypeVulnerability": request.get_type_vulnerability(), "Payload": fuzz_string})
                Utils.print_progress_bar(number, total_len, prefix='Progress:', suffix='Complete', length=50)

    def build_output_file(self, request: RepeaterElement, url: str, cookie: str, payload_req: str):
        placeholder_request = request.get_placeholder_request()
        placeholder_request_copy = copy.deepcopy(placeholder_request)
        placeholder_request_copy.set_url(url)
        placeholder_header_copy = placeholder_request_copy.get_header()
        placeholder_header_copy['Cookie'] = str(cookie.encode('utf8'))
        placeholder_request_copy.set_header(placeholder_header_copy)
        placeholder_request_copy.set_payload(payload_req)

        try:
            response = self.send_request(placeholder_request_copy.get_method(), placeholder_request_copy.get_url(),
                                         placeholder_request_copy.get_header(),
                                         placeholder_request_copy.get_payload())
            response_dict = {
                "url": response.request.url,
                "status_code": response.status_code,
                "header": dict(response.headers),
                "time_elapsed": str(response.elapsed),
                "content_length": len(response.content),
                "html": response.text
            }
        except requests.exceptions.RequestException as e:
            response_dict = {"ERROR": str(e)}

        return [placeholder_request_copy.build_dict(1), response_dict]

    @staticmethod
    def clear_param(param: str, placeholder_separator: str, replace_string: str) -> str:
        return param.replace(placeholder_separator, replace_string)

    def send_request(self, method: str, url: str, header: dict, payload: str):
        payload_dict = dict()
        if len(payload) != 0:
            data = payload.split("§")
            for d in data:
                tmp = d.split("=")
                payload_dict.update({tmp[0]: tmp[1]})
        req = Request(method=method, url=url, headers=header, data=payload_dict)
        prepped = self.s.prepare_request(req)
        # SET TIMEOUT PARAMETERS
        response = self.s.send(prepped, timeout=self.TIMEOUT_VALUE)
        return response

    def finalize_out(self, json_dict: dict):
        print("### (INTRUDER) WAITING FOR... ###")
        with open(self.out_file_path, 'w', encoding="utf-8") as f:
            json.dump(json_dict, f, indent=4)
            print("### LOG INTRUDER CREATED ###\n")
