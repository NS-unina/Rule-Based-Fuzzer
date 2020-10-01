from mitmproxy import proxy, options
from mitmproxy.tools.dump import DumpMaster
from Interceptor import Interceptor
import json


class Mitmproxy:
    PROXY_CONFIG = 'config/proxy.json'

    def __init__(self, url, output_name):
        """
        :param url: URL to intercept
        :param output_name: output file name
        """
        self.url = url
        self.output_name = output_name
        try:
            with open(self.PROXY_CONFIG, encoding='utf-8') as proxy_file:
                mitm_proxy = json.load(proxy_file)
                self.proxy_field = mitm_proxy["mitmproxy_field"]
                self.__run()
        except FileNotFoundError:
            print("The Proxy.json configuration file was not found")
            exit()

    def __run(self):
        opts = options.Options(listen_host=self.proxy_field["listen_host"], listen_port=self.proxy_field["listen_port"])
        pconf = proxy.config.ProxyConfig(opts)
        m = DumpMaster(opts)
        m.server = proxy.server.ProxyServer(pconf)
        m.addons.add(Interceptor(self.url, self.output_name))
        try:
            m.run()
        except KeyboardInterrupt:
            m.shutdown()
