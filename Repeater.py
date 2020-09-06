from requests import Request, Session
from hyper.contrib import HTTP20Adapter
from Utils import Bcolors
import numpy
import inquirer
import json

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
                inquirer.Checkbox('parameters',
                                  message="Choose the parameters where to put the placeholders",
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
            all_parameter = numpy.append(all_parameter, cookie_array)

            questions = [
                inquirer.Checkbox('parameters',
                                  message="Choose the parameters where to put the placeholders",
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

        print(self.parameters_fuzz_list)
        #self.print_placeholder_request()
        self.build_requests()

    # TODO: DA RIFARE LA STAMPA
    """def print_placeholder_request(self):

        # PRINT PARAMETER REQUEST
        placeholder_param = ""
        separator_string = ""
        start_parameter = "?"
        items = self.parameters_dict.items()
        for value in items:
            param_value = value[1]
            if param_value[2] is True:
                placeholder_param = start_parameter + placeholder_param + Bcolors.WARNING + separator_string + param_value[0] + "=$" + param_value[1] + "$" + Bcolors.ENDC
            else:
                placeholder_param = start_parameter + placeholder_param + separator_string + param_value[0] + "=" + param_value[1]
            if placeholder_param != "" and separator_string == "":
                start_parameter = ""
                separator_string = "&"

        # PRINT FIRST LINE REQUEST
        print(self.method + " " + self.base_url + placeholder_param)
        # PRINT HEADERS FIELD EXCEPT COOKIES
        for k, v in self.headers.items():
            if k != "cookie":
                print(k+":"+v)

        # PRINT COOKIES
        printable_cookies = ""
        delimiter_cookie = ""
        head_cookie = "cookie:"
        items = self.cookies_dict.items()
        for value in items:
            cookie_value = value[1]
            if cookie_value[2] is True:
                printable_cookies = head_cookie + printable_cookies + Bcolors.WARNING + cookie_value[0] + "=$" + cookie_value[1] + "$" + Bcolors.ENDC + delimiter_cookie
            else:
                printable_cookies = head_cookie + printable_cookies + cookie_value[0] + "=" + cookie_value[1] + delimiter_cookie
            if delimiter_cookie == "":
                delimiter_cookie = ","
                head_cookie = ""
        print(printable_cookies)"""

    def build_requests(self):
        number_of_request = len(self.fuzz_list["fuzzList"]) * self.number_of_placeholder
        print("Number of request: %s" % number_of_request)

        lock = 0
        couple_temp = ()
        tmp_dict = dict()
        count = 0
        y = 0
        prev = 0
        copy_parameters_fuzz_list = self.parameters_fuzz_list
        # TODO: GENERARE TUTTI PAYLOAD (SNIPER ATTACK)
        for i in range(0, self.number_of_placeholder): # 1
            for j in range(0, len(self.fuzz_list["fuzzList"])):  # 0 - 31    (A,B,C,D)
                fuzz_dict = self.fuzz_list["fuzzList"][j]
                for k in copy_parameters_fuzz_list:
                    if lock != 1:
                        if k[2] is True:
                            prev = count
                            couple_temp = couple_temp + (k[0], fuzz_dict["payload"], k[2], k[3])
                            lock = 1
                        else:
                            couple_temp = couple_temp + (k[0], k[1], k[2], k[3])
                    else:
                        couple_temp = couple_temp + (k[0], k[1], False, k[3])
                    count += 1

                tmp_dict[y] = couple_temp
                couple_temp = ()
                y += 1
                lock = 0
                count = 0
        copy_parameters_fuzz_list[prev][2] = False
        print(tmp_dict)
        # TODO: CREARE UN FILE JSON DI TUTTE LE RICHIESTE SALVATE IN TMP_DICT


    def request(self, method, url, headers=None):

        req = Request(method=method, url=url, headers=headers)
        prepped = self.s.prepare_request(req)
        print("#### REQUEST SENT ####")
        print("......................")
        response = self.s.send(prepped, allow_redirects=True)
        print("REQUEST RESPONSE: %s" % response)
        self.response = response
        return response

