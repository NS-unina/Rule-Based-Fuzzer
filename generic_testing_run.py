import fire
import Utils as u
from Intruder import Intruder
from ManagerObs import ManagerObs
from Mitmproxy import *


def run(url_intercept, out_repeater_file, out_intruder_file, out_obs_file_csv, out_obs_file_json):
    """
    :param url_intercept: url to intercept ( i.e.: http://testphp.vulnweb.com/)
    :param out_repeater_file:  file path for the repeater results (i.e. : results/<file_name>.json)
    :param out_intruder_file: file path for the intruder results (i.e. : results/<file_name>.json)
    :param out_obs_file_csv: file path for the Observer results (i.e. : path/to/file/file.csv)
    :param out_obs_file_json: file path for the Observer results (i.e. :path/to/file/file.json)
    """
    if u.Utils.url_validation(url_intercept):
        Mitmproxy(url_intercept, out_repeater_file)

        i = Intruder(out_repeater_file, out_intruder_file)
        i.run_intruder()

        m = ManagerObs(out_intruder_file)
        m.evaluation(out_obs_file_csv, out_obs_file_json)
    else:
        print("URL Malformed")


if __name__ == '__main__':
    fire.Fire(run)

