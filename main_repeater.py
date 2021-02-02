import fire
import Utils as u
from Repeater.Mitmproxy import Mitmproxy


def run(url, output_file_path):
    if u.Utils.url_validation(url):
        Mitmproxy(url, output_file_path)
    else:
        print("URL Malformed")


# RUN MITMPROXY WITH FIRE LIBRARY
if __name__ == '__main__':
    fire.Fire(run)
