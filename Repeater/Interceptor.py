from Utils import Bcolors
from Repeater.Repeater import Repeater
from mitmproxy import ctx
from mitmproxy import addonmanager
import Utils as u



def e(s):
    print("[-] {}".format(s))
    ctx.master.shutdown()


class Interceptor:

    def __init__(self):
        pass

    def load(self, loader: addonmanager.Loader):
        loader.add_option(
            name="url",
            typespec=str,
            default="http://127.0.0.1:18080/wavsep",
            help="Add a target url",
        )

        loader.add_option(
            name="output",
            typespec=str,
            default="repeater.json",
            help="The output json containing the repeater requests",
        )


    def running(self):
        if u.Utils.url_validation(ctx.options.url):
            self.url = ctx.options.url
            self.output_file = ctx.options.output
            self.repeater = Repeater(self.output_file, False)

        else:
            e("Invalid url")

    def done(self):
        self.repeater.finalizing_out()
        print("### RESULTS EXPORTED TO FILE %s ### --> DONE" % self.output_file)

    def request(self, flow):
        # Fix the localhost 127.0.0.1 conflict
        to_check = self.url.replace("localhost", "127.0.0.1")
        the_url = flow.request.url.replace("localhost", "127.0.0.1")
        if the_url.find(to_check) != -1:
            self.interceptor(flow)

    def response(self, flow):
        to_check = self.url.replace("localhost", "127.0.0.1")
        the_url = flow.request.url.replace("localhost", "127.0.0.1")
        if the_url.find(to_check) != -1:
            self.print_response(flow)

    def interceptor(self, flow):
        self.print_request(flow)
        dict_header = dict()
        dict_form = dict()

        for h in flow.request.headers:
            dict_header.update({h: flow.request.headers[h]})
        for u in flow.request.urlencoded_form:
            dict_form.update({u: flow.request.urlencoded_form[u]})

        self.repeater.setting_request(flow.request.method, flow.request.url, dict_header,
                                        dict_form)

    def interceptor_interactive(self, flow):
        """ Intercept requests by asking

        Args:
            flow (mitmdump flow): The flow
        """
        self.print_request(flow)
        flow.intercept()
        while True:
            choice = input("Intercept this request?: [Y/N] ")
            if choice.lower() == 'y':
                dict_header = dict()
                for h in flow.request.headers:
                    dict_header.update({h: flow.request.headers[h]})

                dict_form = dict()
                for u in flow.request.urlencoded_form:
                    dict_form.update({u: flow.request.urlencoded_form[u]})

                self.repeater.setting_request(flow.request.method, flow.request.url, dict_header,
                                              dict_form)
                break
            if choice.lower() == "n":
                break
        while True:
            choice = input("Exit? [Y/N]")
            if choice.lower() == 'y':
                flow.resume()
                self.repeater.finalizing_out()
                ctx.master.shutdown()
                break
            if choice.lower() == "n":
                break
        flow.resume()

    @staticmethod
    def print_request(flow):
        print(Bcolors.WARNING + "=" * 50 + Bcolors.ENDC)
        print(Bcolors.WARNING + flow.request.method + " " + flow.request.path + " " + flow.request.http_version
              + Bcolors.ENDC)
        print(Bcolors.WARNING + "-" * 50 + "request headers:" + Bcolors.ENDC)
        for k, v in flow.request.headers.items():
            print(Bcolors.WARNING + "%-20s: %s" % (k.upper(), v) + Bcolors.ENDC)
        param_post = ""
        for k in flow.request.urlencoded_form:
            param_post = param_post + k + "=" + flow.request.urlencoded_form[k] + " "
        if param_post != "":
            print(Bcolors.WARNING + param_post + Bcolors.ENDC)

    @staticmethod
    def print_response(flow):
        print(Bcolors.OKBLUE + "-" * 50 + "response headers:" + Bcolors.ENDC)
        for k, v in flow.response.headers.items():
            print(Bcolors.OKBLUE + "%-20s: %s" % (k.upper(), v) + Bcolors.ENDC)
