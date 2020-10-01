import fire
from Mitmproxy import Mitmproxy


# ENTRY POINT MITMPROXY
def run(url, out):
    """
    :param url: url to intercept
    :param out: name of the output file
    """
    Mitmproxy(url, out)


# RUN MITMPROXY WITH FIRE LIBRARY
if __name__ == '__main__':
    fire.Fire(run)

