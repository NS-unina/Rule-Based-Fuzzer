from Utils import Utils
from requests import Request, Session
from hyper.contrib import HTTP20Adapter
import inquirer
import json
import copy


class Repeater:
    DIRECTORY_OUTPUT = "results/"

    def __init__(self, output_name):
        self.s = Session()
        self.s.mount('https://', HTTP20Adapter())
        self.output_name = output_name
        self.json_out = []

    def setting_request(self, method, url, headers, urlencoded_form):
        url_split_array = url.split("?")
        base_url = url_split_array[0]
        url_string_placeholder = base_url

        # Check and set the parameters in the URL
        if len(url_split_array) != 1:
            param_array = url_split_array[1].split("&")
            param_choice = self.__choice("Choose the parameters where to put the placeholders (URL)", param_array)
            url_string_placeholder = url_string_placeholder + "?" + self.__header_process(param_array, param_choice, "&")

        # Cookie control
        cookie_string_placeholder = ""
        cookie_dict_value = headers.get("Cookie")
        if cookie_dict_value is not None:
            cookie_array = cookie_dict_value.split(";")
            cookie_choice = self.__choice("Choose the parameters where to put the placeholders (COOKIE)", cookie_array)
            cookie_string_placeholder = self.__header_process(cookie_array, cookie_choice, ";")

        param_post = []
        param_post_placeholder = ""
        param_post_string = ""
        if len(urlencoded_form) != 0:
            i = 0
            for k in urlencoded_form:
                param_post.append(k + "=" + urlencoded_form[k])
                i = i+1

            post_param_choice = self.__choice("Choose the parameters where to put the placeholders (POST)",param_post)
            param_post_placeholder = self.__header_process(param_post, post_param_choice, "&")
            param_post_string = self.__header_process(param_post, {"parameters": []}, "&")

        # Send valid request
        response = self.__send_request(method, url, headers)

        placeholder_string_dict = {
            "URL": url_string_placeholder,
            "COOKIE": cookie_string_placeholder,
            "POST": param_post_placeholder
        }

        # CREATE JSON OUTPUT
        self.__build_output(response, placeholder_string_dict, param_post_string)

    def __build_output(self, response, placeholder_string_dict, param_post_string):
        dict_valid_request = {"Request": {
            "method": response.request.method,
            "url": response.request.url,
            "headers": dict(response.request.headers),
            "payload request": param_post_string
        }}
        dict_valid_response = {"Response": {
            "URL": response.request.url,
            "status_code": response.status_code,
            "header": Utils.convert_utf8(response.headers),
            "time_elapsed": str(response.elapsed),
            "html": response.text
        }}
        placeholder_dict = copy.deepcopy(dict_valid_request)
        placeholder_dict["Request"]["url"] = placeholder_string_dict["URL"]
        placeholder_dict["Request"]["headers"]["Cookie"] = placeholder_string_dict["COOKIE"]
        placeholder_dict["Request"]["payload request"] = placeholder_string_dict["POST"]
        self.json_out.append({"ValidRequest": [dict_valid_request, dict_valid_response],
                              "PlaceholderRequest": placeholder_dict})

    def finalizing_out(self):
        with open(self.DIRECTORY_OUTPUT+self.output_name, 'w', encoding="utf-8") as f:
            json.dump(self.json_out, f, indent=4, ensure_ascii=False)

    def __send_request(self, method, url, headers):
        """
        :return: response HTTP
        """
        req = Request(method=method, url=url, headers=headers)
        prepped = self.s.prepare_request(req)
        response = self.s.send(prepped)
        return response

    # BUILD A HEADER STRING
    @staticmethod
    def __header_process(field_array, choice, separator) -> str:
        """
        :param field_array: Header fields
        :type field_array: list
        :param choice: array of choices
        :type choice: dict
        :param separator: character separator
        :type separator: str
        :return: str
        """
        placeholder_string = ""
        flag_first = True
        for k in field_array:
            parameter_parts = k.split("=", 1)
            if k in choice["parameters"]:
                tmp_string = parameter_parts[0] + "=" + "$" + parameter_parts[1] + "$"
            else:
                tmp_string = parameter_parts[0] + "=" + parameter_parts[1]
            if flag_first is True:
                placeholder_string += tmp_string
                flag_first = False
            else:
                placeholder_string += separator + tmp_string
        return placeholder_string

    @staticmethod
    def __choice(message, choices):
        """
        :param message: question message
        :type message: str
        :param choices: array of choices
        :type choices: list
        :return: selected choices
        :type return: list
        """
        questions = [
            inquirer.Checkbox(
                'parameters',
                message=message,
                choices=choices,
            ),
        ]
        param_choice = inquirer.prompt(questions)
        return param_choice

