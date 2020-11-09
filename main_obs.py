import fire
from ManagerObs import ManagerObs


# ENTRY POINT INTRUDER
def run(file, csv_out, json_out):
    """
    :param json_out: file path for the Observer results (i.e. : path/to/file/file.json)
    :param csv_out: file path for the Observer results (i.e. : path/to/file/file.csv)
    :param file:  file path for the intruder results (i.e. : results/<file_name>.json)
    :return:
    """
    m = ManagerObs(file)
    m.evaluation(csv_out, json_out)


# RUN MANAGER OBS WITH FIRE LIBRARY
if __name__ == '__main__':
    fire.Fire(run)
