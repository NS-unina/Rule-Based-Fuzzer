from Utils import Bcolors
from Repeater import Repeater
from mitmproxy import ctx


class Interceptor:

    def __init__(self, url):
        # URL DA INTERCETTARE
        self.url = url

    def request(self, flow):
        # TODO: CONTROLLARE SE FLOW.REQUEST.HEADERS ESISTE PRIMA DEL FIND
        if flow.request.url.find(self.url) != -1:
            self.print_request(flow)
            flow.intercept()
            choice = input("Intercept this request?: [Y/N] ")
            if choice == "Y" or choice == 'y':
                print("REQUEST INTERCEPTED, SENT TO THE REPEATER")
                repeater = Repeater(flow.request.method, flow.request.url, flow.request.headers)
                ctx.master.shutdown()
                repeater.setting_request()
            else:
                flow.resume()
            print("\n")

    def response(self, flow):
        if flow.request.url.find(self.url) != -1:
            self.print_response(flow)

    @staticmethod
    def print_request(flow):
        print(Bcolors.WARNING+"=" * 50+Bcolors.ENDC)
        print(Bcolors.WARNING + flow.request.method + " " + flow.request.path + " " + flow.request.http_version
              + Bcolors.ENDC)
        print(Bcolors.WARNING + "-" * 50 + "request headers:" + Bcolors.ENDC)
        for k, v in flow.request.headers.items():
            print(Bcolors.WARNING+"%-20s: %s" % (k.upper(), v) + Bcolors.ENDC)

    @staticmethod
    def print_response(flow):
        print(Bcolors.OKBLUE + "-" * 50 + "response headers:" + Bcolors.ENDC)
        for k, v in flow.response.headers.items():
            print(Bcolors.OKBLUE + "%-20s: %s" % (k.upper(), v) + Bcolors.ENDC)
