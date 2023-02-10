import fire
from Intruder.Intruder import Intruder


def run(repeater, intruder, verbose=False):
    i = Intruder(repeater, intruder, verbose)
    i.execute()


if __name__ == '__main__':
    fire.Fire(run)
