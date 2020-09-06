from Utils import Bcolors
from Repeater import Repeater


class Interceptor:

    def __init__(self, m, url):
        self.m = m

        # URL DA INTERCETTARE
        self.url = url

    def request(self, flow):
        if self.url.find(flow.request.headers["host"]) != -1:
            self.print_request(flow)
            flow.intercept()
            choice = input("Intercept this request?: [Y/N] ")
            if choice == "Y" or choice == 'y':
                print("REQUEST INTERCEPTED, SENT TO THE REPEATER")
                repeater = Repeater(flow.request.method, flow.request.url, flow.request.headers)
                self.m.shutdown()
                repeater.setting_request()
            else:
                flow.resume()
            print("\n")

    def response(self, flow):
        if self.url.find(flow.request.headers["host"]) != -1:
            self.print_response(flow)

    def print_request(self, flow):

        print("")
        print(Bcolors.WARNING+"=" * 50+Bcolors.ENDC)
        # print("FOR: " + flow.request.url)
        print(Bcolors.WARNING + flow.request.method + " " + flow.request.path + " " + flow.request.http_version
              + Bcolors.ENDC)

        print(Bcolors.WARNING + "-" * 50 + "request headers:" + Bcolors.ENDC)
        for k, v in flow.request.headers.items():
            print(Bcolors.WARNING+"%-20s: %s" % (k.upper(), v) + Bcolors.ENDC)

    def print_response(self, flow):
        print(Bcolors.OKBLUE + "-" * 50 + "response headers:" + Bcolors.ENDC)
        for k, v in flow.response.headers.items():
            print(Bcolors.OKBLUE + "%-20s: %s" % (k.upper(), v) + Bcolors.ENDC)
