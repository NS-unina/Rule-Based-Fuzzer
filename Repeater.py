from requests import Request, Session
from hyper.contrib import HTTP20Adapter
from Utils import Bcolors
import numpy
import inquirer
import json
import copy
"""
PAYLOAD LEGENDA
1:SQLi	Errori SQL, pagina a contenuto vuoto o differente, errore HTTP
2:Ritardo nella risposta HTTP, errore HTTP
3:Richiesta HTTP ricevuta sul server personale, errori nell’a risposta HTTP 
4: <string> presente nella risposta HTTP
"""


class Repeater:
    forms = ""
    base_url = ""
    parameters_dict = dict()
    # SERVE PER IL PRINT
    placeholder_param = ""
    cookies_dict = dict()
    number_of_placeholder = 0

    printable_param = []
    printable_cookie = []

    def __init__(self, method, url, headers):
        self.parameters_fuzz_list = []
        self.s = Session()
        self.s.mount('http://', HTTP20Adapter())
        self.s.mount('https://', HTTP20Adapter())
        self.method = method
        self.url = url
        self.headers = headers
        with open('config/fuzz_list.json', encoding='utf-8') as json_file:
            self.fuzz_list = json.load(json_file)
        # TODO: Init dictionary delle osservazioni

    def setting_request(self):
        print("### SETTING REQUEST ###")
        url_split_array = self.url.split("?")
        self.base_url = url_split_array[0]
        index = 0
        all_parameter = []
        if len(url_split_array) != 1:
            # SE CI SONO PARAMETRI FACCIO SCEGLIERE QUALI POSIZIONI UTILIZZARE PER L'ATTACCO
            param_array = url_split_array[1].split("&")
            self.printable_param = param_array # PRINT
            all_parameter = param_array # PER AVERE TUTTI I PARAMETRI

            questions = [
                inquirer.Checkbox(
                    'parameters',
                    message="Choose the parameters where to put the placeholders (URL)",
                    choices=param_array,
                ),
            ]
            param_choice = inquirer.prompt(questions)

            for k in param_array:
                parameter_parts = k.split("=", 1)
                if k in param_choice["parameters"]:
                    self.number_of_placeholder += 1
                    self.parameters_fuzz_list.insert(index, [parameter_parts[0], parameter_parts[1], True, "URL"])
                else:
                    self.parameters_fuzz_list.insert(index, [parameter_parts[0], parameter_parts[1], False, "URL"])
                index += 1

        # CONTROLLO DEL COOKIE
        cookie_dict_value = self.headers.get("Cookie")
        if cookie_dict_value is not None:
            cookie_array = cookie_dict_value.split(";")
            self.printable_cookie = cookie_array # PRINT
            # all_parameter = numpy.append(all_parameter, cookie_array)

            questions = [
                inquirer.Checkbox('parameters',
                                  message="Choose the parameters where to put the placeholders (COOKIE)",
                                  choices=cookie_array,
                                  ),
            ]
            cookie_choice = inquirer.prompt(questions)
            for k in cookie_array:
                parameter_parts = k.split("=", 1)
                if k in cookie_choice["parameters"]:
                    self.number_of_placeholder += 1
                    self.parameters_fuzz_list.insert(index, [parameter_parts[0], parameter_parts[1], True, "Cookie"])
                else:
                    self.parameters_fuzz_list.insert(index, [parameter_parts[0], parameter_parts[1], False, "Cookie"])
                index += 1

        # TODO: Recuperare i paramentri di richieste POST

        self.build_requests()

    def build_requests(self):
        json_dict = json.loads('{"Requests": []}')
        json_req = json_dict["Requests"]
        y = 0
        prev = 0

        # PREPARO UN DIZIONARIO PER L'HEADER
        header_dict = dict()
        for k, v in self.headers.items():
            header_dict[k] = v

        # GENERO TUTTE LE POSSIBILI RICHIESTE
        for i in range(0, self.number_of_placeholder): # 1
            for j in range(0, len(self.fuzz_list["fuzzList"])):  # 0 - 31    (A,B,C,D)
                fuzz_dict = self.fuzz_list["fuzzList"][j]
                param_url = ""
                param_cookie = ""
                lock = 0
                count = 0
                for k in self.parameters_fuzz_list:
                    value_param = k[1]
                    if lock != 1:
                        if k[2] is True:
                            prev = count
                            value_param = fuzz_dict["payload"]
                            lock = 1
                    if k[3] == "URL":
                        if param_url == "":
                            param_url = "?" + param_url + k[0] + "=" + value_param
                        else:
                            param_url = param_url + "&" + k[0] + "=" + value_param
                    else:
                        if param_cookie == "":
                            param_cookie = param_cookie + k[0] + "=" + value_param
                        else:
                            param_cookie = param_cookie + ";" + k[0] + "=" + value_param
                    count += 1
                tmp_copy = copy.deepcopy(header_dict)
                tmp_copy.update({'Cookie': param_cookie})
                json_req.append(
                    {"index": y, "method": self.method, "URL": self.base_url+param_url, "param": param_url, "cookie": param_cookie,
                     "header": tmp_copy, "payload": fuzz_dict["payload"]})
                y += 1
        self.parameters_fuzz_list[prev][2] = False

        # OUTPUT SU FILE JSON
        with open('results/requests.json', 'w', encoding='utf-8') as f:
            json.dump(json_dict, f, indent=4, ensure_ascii=False)
        self.repeat_request()

    def repeat_request(self):
        json_dict = json.loads('{"Response": []}')
        json_resp = json_dict["Response"]
        with open('results/requests.json', encoding='utf-8') as json_file:
            request_json = json.load(json_file)
        print("CREATE RESPONSE LOG...")
        for i in request_json["Requests"]:
            req = Request(method=i["method"], url=i["URL"], headers=i["header"])
            prepped = self.s.prepare_request(req)
            response = self.s.send(prepped)
            # TODO: GENERARE LE OSSERVAZIONI

            # CONVERT BYTE DICTIONARY IN DICTIONARY OF STRING
            dict_headers = self.convert(response.headers)
            json_resp.append(
                {"id": i["index"], "URL": response.request.url, "status_code": response.status_code,
                 "header": dict_headers, "time_elapsed": str(response.elapsed), "observation": [], "html": response.text})
        # OUTPUT SU FILE JSON
        with open('results/response.json', 'w', encoding="utf-8") as f:
            json.dump(json_dict, f, indent=4, ensure_ascii=False)
            print("DONE")

    @staticmethod
    def convert(data):
        convert_dict = {}
        for key, value in data.items():
            convert_dict[key.decode("utf-8")] = value.decode("utf-8")
        return convert_dict
