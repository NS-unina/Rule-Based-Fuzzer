import fire
from Analyzer.Analyzer import Analyzer


def run(intruder_file_path, repeater_file_path, csv_out, json_out):
    m = Analyzer(intruder_file_path, repeater_file_path)
    m.evaluation(csv_out, json_out)


if __name__ == '__main__':
    fire.Fire(run)
