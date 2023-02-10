import fire

from Oracle.Oracle import Oracle


def run(analyzer, oracle, csv):
    oracle = Oracle(analyzer, oracle, csv)
    oracle.execute()


if __name__ == '__main__':
    fire.Fire(run)
