import fire
from Intruder.Intruder import Intruder


def run(repeater_file_path, out_file_path):
    i = Intruder(repeater_file_path, out_file_path)
    i.execute()


if __name__ == '__main__':
    fire.Fire(run)
