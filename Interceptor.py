from Utils import Bcolors
from Repeater import Repeater
from mitmproxy import ctx


class Interceptor:

    def __init__(self, url, output_name):
        self.url = url
        self.output_file = output_name
        self.repeater = Repeater(output_name)
        self.exit_flag = False

    def clientdisconnect(self, layer):
        if self.exit_flag is True:
            try:
                ctx.master.shutdown()
                print("### RESULTS EXPORTED TO FILE %s ### --> DONE" % self.output_file)
            except ValueError:
                print("MITMPROXY: %s" % ValueError)

    def request(self, flow):
        if flow.request.url.find(self.url) != -1 and self.exit_flag is False:
            self.print_request(flow)
            flow.intercept()
            while True:
                choice = input("Intercept this request?: [Y/N] ")
                if choice.lower() == 'y':
                    self.repeater.setting_request(flow.request.method, flow.request.url, flow.request.headers,
                                              flow.request.urlencoded_form)
                    break
                if choice.lower() == "n":
                    break

            while True:
                choice = input("Exit? [Y/N]")
                if choice.lower() == 'y':
                    self.repeater.finalizing_out()
                    self.exit_flag = True
                    break
                if choice.lower() == "n":
                    break

            flow.resume()
            print("\n")


    def response(self, flow):
        if flow.request.url.find(self.url) != -1 and self.exit_flag is False:
            self.print_response(flow)
        print("ASPETTO")
        print(flow)

    @staticmethod
    def print_request(flow):
        print(Bcolors.WARNING+"=" * 50+Bcolors.ENDC)
        print(Bcolors.WARNING + flow.request.method + " " + flow.request.path + " " + flow.request.http_version
              + Bcolors.ENDC)
        print(Bcolors.WARNING + "-" * 50 + "request headers:" + Bcolors.ENDC)
        for k, v in flow.request.headers.items():
            print(Bcolors.WARNING+"%-20s: %s" % (k.upper(), v) + Bcolors.ENDC)
        param_post = ""
        for k in flow.request.urlencoded_form:
            param_post = param_post + k + "=" + flow.request.urlencoded_form[k]+ " "
        if param_post != "":
            print(Bcolors.WARNING + param_post + Bcolors.ENDC)


    @staticmethod
    def print_response(flow):
        print(Bcolors.OKBLUE + "-" * 50 + "response headers:" + Bcolors.ENDC)
        for k, v in flow.response.headers.items():
            print(Bcolors.OKBLUE + "%-20s: %s" % (k.upper(), v) + Bcolors.ENDC)
