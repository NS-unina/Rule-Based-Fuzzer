import fire
from Analyzer.Analyzer import Analyzer


def run(intruder_file_path, repeater_file_path, analyzer_file_path):
    m = Analyzer(intruder_file_path, repeater_file_path)
    m.evaluation(analyzer_file_path)


if __name__ == '__main__':
    fire.Fire(run)
