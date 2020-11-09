import fire
from Intruder import Intruder


# ENTRY POINT INTRUDER
def run(inp, out):
    """
    :param out:
    :param inp: repeater output file
    """
    i = Intruder(inp, out)
    i.run_intruder()


# RUN INTRUDER WITH FIRE LIBRARY
if __name__ == '__main__':
    fire.Fire(run)



