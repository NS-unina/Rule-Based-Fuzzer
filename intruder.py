import fire
from Intruder.Intruder import Intruder


def run(repeater, intruder):
    i = Intruder(repeater, intruder)
    i.execute()


if __name__ == '__main__':
    fire.Fire(run)
