import fire
import Utils as u
from Intruder.Intruder import Intruder
from Analyzer.Analyzer import Analyzer
from Oracle.Oracle import Oracle
from Repeater.Mitmproxy import *

# generic_testing_run.py http://testphp.vulnweb.com/ results/repeater.json results/intruder.json results/observer.csv results/observer.json
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

        intruder = Intruder(out_repeater_file, out_intruder_file)
        intruder.execute()

        analyzer = Analyzer(out_intruder_file)
        analyzer.evaluation(out_obs_file_csv, out_obs_file_json)
        oracle = Oracle(out_obs_file_json)
        oracle.execute()
    else:
        print("URL Malformed")


if __name__ == '__main__':
    fire.Fire(run)

