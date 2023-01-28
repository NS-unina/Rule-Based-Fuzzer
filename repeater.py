import fire
import Utils as u
from mitmproxy import ctx
from Repeater.Interceptor import Interceptor

# def e():
#     ctx.master.shutdown()


# def run(url, output_file_path):
#     if u.Utils.url_validation(url):
#         addons = [Interceptor(url, output_file_path)]
#     else:
#         print("URL Malformed")
#         ctx.master.shutdown()


addons = [Interceptor()]