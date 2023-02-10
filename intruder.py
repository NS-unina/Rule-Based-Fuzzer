import fire
from Intruder.Intruder import Intruder


def run(repeater, output):
    i = Intruder(repeater, output)
    i.execute()


if __name__ == '__main__':
    fire.Fire(run)
