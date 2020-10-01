import fire
from Intruder import Intruder


# ENTRY POINT INTRUDER
def run(file):
    """
    :param file: repeater output file
    """
    i = Intruder(file)
    i.run_intruder()


# RUN INTRUDER WITH FIRE LIBRARY
if __name__ == '__main__':
    fire.Fire(run)



