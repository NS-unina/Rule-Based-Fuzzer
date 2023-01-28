import fire

from Oracle.Oracle import Oracle


def run(analyzer_file_path, oracle_file_path, oracle_file_path_csv):
    oracle = Oracle(analyzer_file_path, oracle_file_path, oracle_file_path_csv)
    oracle.execute()


if __name__ == '__main__':
    fire.Fire(run)
