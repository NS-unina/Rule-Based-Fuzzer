import fire
from Intruder.Intruder import Intruder


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
    #fire.Fire(run)
    inp = 'results/repeater.json'
    out = 'results/intruder.json'
    i = Intruder(inp, out)
    i.execute()
    #i.run_intruder()



