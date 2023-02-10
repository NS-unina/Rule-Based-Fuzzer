import fire
from Analyzer.Analyzer import Analyzer


def run(intruder, repeater, analyzer):
    m = Analyzer(intruder, repeater)
    m.evaluation(analyzer)


if __name__ == '__main__':
    fire.Fire(run)
