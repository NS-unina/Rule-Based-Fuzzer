import json 
import os
import typer

def my_function(arg1: str, arg2: int, opt_arg1: str = "default1", opt_arg2: int = 0):
    typer.echo(f"arg1: {arg1}")
    typer.echo(f"arg2: {arg2}")
    typer.echo(f"opt_arg1: {opt_arg1}")
    typer.echo(f"opt_arg2: {opt_arg2}")


HAR_FOLDER = "owasp-sessions"

def to_dict(l: list):
    """Generate a dictionary from an array

    Args:
        l (list): A list 

    Returns:
        dict: A dictionary
    """
    ret = {}
    for i in l:
        ret[i['name']] = i['value']
    return ret


class Request: 
    def __init__(self, url, method, cookies, headers, body = ""):
        self.url = url
        self.method = method 
        self.cookies = to_dict(cookies)
        self.headers = to_dict(headers)
        self.body = body
# class HarEntry:

def get_har_file(filename):
    return os.path.join(HAR_FOLDER, filename)

def get_categories():
    return os.listdir(HAR_FOLDER)


def _get_har_sessions(category):
    return [f for f in os.listdir(os.path.join(HAR_FOLDER, category)) if os.path.isfile(os.path.join(HAR_FOLDER, category, f))] 


def get_har_sessions(category = None):
    return [f for f in os.listdir(HAR_FOLDER) if os.path.isfile(os.path.join(HAR_FOLDER, f))]




class HarParser:
    def from_file(har_file):
        requests = []
        with open(har_file) as f:
            data = json.load(f)

        entries = data['log']['entries']
        for e in entries: 
            req = e['request']
            req_obj = Request(req['url'], req['method'], req['cookies'], req['headers'])
            requests.append(req_obj)
            if req['method'] == "POST":
                req_obj.body = to_dict(req['postData']['params'])

        return requests

