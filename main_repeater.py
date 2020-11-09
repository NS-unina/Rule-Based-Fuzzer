import fire
import Utils as u
from Mitmproxy import Mitmproxy

"""
TODO: MODALITA' INTERATTIVA -i O BRUTE FORCE -b 
"""


# ENTRY POINT MITMPROXY
def run(url, out):
    """
    :param url: url to intercept
    :param out: name of the output file
    """
    if u.Utils.url_validation(url):
        Mitmproxy(url, out)
    else:
        print("URL Malformed")


# RUN MITMPROXY WITH FIRE LIBRARY
if __name__ == '__main__':
    fire.Fire(run)