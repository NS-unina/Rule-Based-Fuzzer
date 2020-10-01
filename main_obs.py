import fire
from ManagerObs import ManagerObs


# ENTRY POINT INTRUDER
def run(file):
    """
    :param file: intruder output file
    :return:
    """
    m = ManagerObs(file)
    m.evaluation()


# RUN MANAGER OBS WITH FIRE LIBRARY
if __name__ == '__main__':
    fire.Fire(run)
