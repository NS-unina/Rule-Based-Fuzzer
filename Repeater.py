from requests import Request, Session
import inquirer
import json


class Repeater:
    INTERACTIVE = False

    def __init__(self,  output_name, interactive):
        self.s = Session()
        self.output_name = output_name
        self.json_out = dict()
        self.num = 1
        self.INTERACTIVE = interactive

    def setting_request(self, method: str, url: str, headers: dict, urlencoded_form: dict):

        url_split_array = url.split("?")
        base_url = url_split_array[0]
        url_string_placeholder = base_url

        # Check and set the parameters in the URL
        if len(url_split_array) != 1:
            param_array = url_split_array[1].split("&")
            if self.INTERACTIVE is True:
                param_choice = self.__choice("Choose the parameters where to put the placeholders (URL)", param_array)
            else:
                param_choice = {'parameters': param_array}

            url_string_placeholder = url_string_placeholder + "?" + self.__header_process(param_array, param_choice, "&")

        # Cookie control
        cookie_string_placeholder = ""
        cookie_dict_value = headers.get("Cookie")
        if cookie_dict_value is not None:
            cookie_array = cookie_dict_value.split(";")
            if self.INTERACTIVE is True:
                cookie_choice = self.__choice("Choose the parameters where to put the placeholders (COOKIE)", cookie_array)
            else:
                cookie_choice = {'parameters': cookie_array}

            cookie_string_placeholder = self.__header_process(cookie_array, cookie_choice, ";")

        # POST control
        param_post = []
        param_post_placeholder = ""
        param_post_string = ""
        if len(urlencoded_form) != 0:
            i = 0
            for k in urlencoded_form:
                param_post.append(k + "=" + urlencoded_form[k])
                i = i+1
            if self.INTERACTIVE is True:
                post_param_choice = self.__choice("Choose the parameters where to put the placeholders (POST)", param_post)
            else:
                post_param_choice = {'parameters': param_post}

            param_post_placeholder = self.__header_process(param_post, post_param_choice, "§")
            param_post_string = self.__header_process(param_post, {"parameters": []}, "§")

        # Send valid request
        response = self.__send_request(method, url, headers, urlencoded_form)

        placeholder_string_dict = {
            "URL": url_string_placeholder,
            "COOKIE": cookie_string_placeholder,
            "POST": param_post_placeholder
        }

        # CREATE JSON OUTPUT
        self.__build_output(response, placeholder_string_dict, param_post_string, self.num)
        self.num += 1

    def __build_output(self, response, placeholder_string_dict, param_post_string, num):

        tmp = dict(response.request.headers)
        if 'Cookie' in tmp:
            tmp["Cookie"] = placeholder_string_dict["COOKIE"]
        dict_out = {
            "id_fuzz_"+str(num): {
                "Request": {
                    "method": response.request.method,
                    "url": response.request.url,
                    "headers": dict(response.request.headers),
                    "payload request": param_post_string
                },
                "Response": {
                    "URL": response.request.url,
                    "status_code": response.status_code,
                    "header": dict(response.headers),
                    "time_elapsed": str(response.elapsed),
                    "content_length": len(response.content),
                    "html": response.text
                },
                "PlaceholderRequest": {
                    "method": response.request.method,
                    "url": placeholder_string_dict["URL"],
                    "headers": tmp,
                    "payload request": placeholder_string_dict["POST"]
                }
            }
        }
        self.json_out.update(dict_out)

    def finalizing_out(self):
        with open(self.output_name, 'w', encoding="utf-8") as f:
            json.dump(self.json_out, f, indent=4, ensure_ascii=False)

    def __send_request(self, method, url, headers, data):
        """
        :return: response HTTP
        """
        req = Request(method=method, url=url, headers=headers, data=data)
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

