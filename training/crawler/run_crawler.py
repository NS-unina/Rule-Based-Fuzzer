import os
import sys

import argparse


from har_manager import send_from_har
from my_har_parser import get_har_file, get_categories,get_har_sessions


parser = argparse.ArgumentParser(description='Run crawler')
parser.add_argument('host', nargs='?', default="")
parser.add_argument('port', nargs='?', default="")
parser.add_argument('category', nargs='?', default="")
parser.add_argument('harfile', nargs='?', default="")

args = parser.parse_args()




def e():
    sys.exit(-1)

def usage():
    print("[-] Usage: run_crawler.py <host> <port> <category> <harfile>")
    e()

har_sessions = get_har_sessions()


print("Sessions")
print(har_sessions)
for s in har_sessions:
    filepath = get_har_file(s)
    print("[+] Scanning {} har file ".format(filepath))
    send_from_har(filepath, "http://{}:{}".format(args.host, args.port) if args.host else None)
