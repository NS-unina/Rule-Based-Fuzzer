import fire
import Utils as u
from Intruder.Intruder import Intruder
from Analyzer.Analyzer import Analyzer
from Oracle.Oracle import Oracle
from Repeater.Mitmproxy import *


def run(url_intercept, repeater_file_path, intruder_file_path, analyzer_file_path_csv, analyzer_file_path_json,
        oracle_file_path, oracle_file_path_csv):
    """
    :param url_intercept: url to intercept ( i.e.: http://testphp.vulnweb.com/)
    :param repeater_file_path:  file path for the repeater results (i.e. : results/<file_name>.json)
    :param intruder_file_path: file path for the intruder results (i.e. : results/<file_name>.json)
    :param analyzer_file_path_csv: file path for the Analyzer results (i.e. : path/to/file/file.csv)
    :param analyzer_file_path_json: file path for the Analyzer results (i.e. :path/to/file/file.json)
    :param oracle_file_path: file path for the Oracle results (i.e. :path/to/file/file.json)
    :param oracle_file_path_csv: file path for the Oracle results (i.e. :path/to/file/file.json)
    """
    if u.Utils.url_validation(url_intercept):
        Mitmproxy(url_intercept, repeater_file_path)

        intruder = Intruder(repeater_file_path, intruder_file_path)
        intruder.execute()

        analyzer = Analyzer(intruder_file_path, repeater_file_path)
        analyzer.evaluation(analyzer_file_path_csv, analyzer_file_path_json)
        oracle = Oracle(analyzer_file_path_json, oracle_file_path, oracle_file_path_csv)
        oracle.execute()
    else:
        print("URL Malformed")


if __name__ == '__main__':
    fire.Fire(run)
