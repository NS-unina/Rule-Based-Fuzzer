import sys
import fire
from Mitmproxy import Mitmproxy
# main_repeater.py
"""arguments = len(sys.argv) - 1
if arguments == 4:
    # Output argument-wise
    if sys.argv[1] == "--url":
        url = sys.argv[2]
        if sys.argv[3] == "--out":
            output_name = sys.argv[4]
        else:
            print("Run the script with the following parameters: --url <value> --out <value> .json")
            exit()
    else:
        print("Run the script with the following parameters: --url <value> --out <value> .json")
        exit()
else:
    print("Run the script with the following parameters: --url <value> --out <value> .json")
    exit()"""

if __name__ == '__main__':
    fire.Fire(Mitmproxy)

"""m = Mitmproxy(url, output_name)
m.run()"""

