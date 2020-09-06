from mitmproxy import proxy, options
from mitmproxy.tools.dump import DumpMaster
from Interceptor import Interceptor

# TODO: PASSARE DA LINEA DI COMANDO
listen_host = "127.0.0.1"
listen_port = 8080
url = "https://ac711f1c1fd25ea180010b6a00b300fa.web-security-academy.net/"

opts = options.Options(listen_host=listen_host, listen_port=listen_port)
pconf = proxy.config.ProxyConfig(opts)
m = DumpMaster(opts)
m.server = proxy.server.ProxyServer(pconf)
m.addons.add(Interceptor(m, url))

try:
    m.run()
except KeyboardInterrupt:
    m.shutdown()



