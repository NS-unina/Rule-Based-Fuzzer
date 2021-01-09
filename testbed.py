import os
from Intruder.Intruder import Intruder
from Analyzer.Analyzer import Analyzer
from Repeater.Repeater import *
import csv
from datetime import datetime
from bs4 import BeautifulSoup

REPEATER_PATH_FILE = "results/repeater.json"
INTRUDER_PATH_FILE = "results/intruder.json"
OBS_PATH_DIR = r"testbed/Observation/"
PATH_TESTBED = r"C:testbed/"
FILE_NAME_TESTBED = "TestBed-short.CSV"
PREFIX_TESTBED = "Testbed_"


def extract_form_fields(soup):
    "Turn a BeautifulSoup form in to a dict of fields and default values"
    fields = {}
    for input in soup.findAll('input'):
        # ignore submit/image with no name attribute
        if input['type'] in ('submit', 'image') and not input.has_attr('name'):
            continue

        # single element nome/value fields
        if input['type'] in ('text', 'hidden', 'password', 'submit', 'image'):
            value = ''
            if input.has_attr('value'):
                value = input['value']
            fields[input['name']] = value
            continue

        # checkboxes and radios
        if input['type'] in ('checkbox', 'radio'):
            value = ''
            if input.has_attr('checked'):
                if input.has_attr('value'):
                    value = input['value']
                else:
                    value = 'on'
            if fields.has_attr(input['name']) and value:
                fields[input['name']] = value

            if not fields.has_attr(input['name']):
                fields[input['name']] = value

            continue

        assert False, 'input type %s not supported' % input['type']

    # textareas
    for textarea in soup.findAll('textarea'):
        fields[textarea['name']] = textarea.string or ''

    # select fields
    for select in soup.findAll('select'):
        value = ''
        options = select.findAll('option')
        is_multiple = select.has_attr('multiple')
        selected_options = [
            option for option in options
            if option.has_attr('selected')
        ]

        # If no select options, go with the first one
        if not selected_options and options:
            selected_options = [options[0]]

        if not is_multiple:
            assert (len(selected_options) < 2)
            if len(selected_options) == 1:
                value = selected_options[0]['value']
        else:
            value = [option['value'] for option in selected_options]

        fields[select['name']] = value

    return fields


def init_session(session, url):
    try:
        req = Request('GET', url=url, headers=dict(), data=dict())
        prepped = session.prepare_request(req)
        session.send(prepped)
    except Exception:
        print("Error: Session not initialized")
        exit()


def wavsep_testbed_run():
    # CREATE A SESSION
    s = Session()
    flag_init_session = True
    with open(PATH_TESTBED+FILE_NAME_TESTBED, newline='') as csv_file:
        reader = csv.reader(csv_file, delimiter=';', quotechar='|')
        header_row = False
        rep = Repeater(REPEATER_PATH_FILE, False)
        for row in reader:
            if header_row:
                ID_REQ = row[0]
                TITLE = row[1]
                METHOD = row[2]
                BASE_URL = row[3]
                URL = row[4]
                INJECTION_TYPE = row[5]
                FULL_URL = BASE_URL + URL
                if flag_init_session:
                    init_session(s, FULL_URL)
                    flag_init_session = False

                ###########################
                # RUN REPEATER
                r = Request('GET', url=FULL_URL, headers=dict(), data=dict())
                prepped = s.prepare_request(r)
                response = s.send(prepped)

                if METHOD == "GET":
                    rep.setting_request(METHOD, r.url, response.request.headers, dict())
                    rep.finalizing_out()
                else:
                    DIR_NAME = os.path.dirname(FULL_URL)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = soup.find_all('form')
                    for f in forms:
                        results = extract_form_fields(f)
                        URL_POST = DIR_NAME + '/' + f['action']
                        rep.setting_request(METHOD, URL_POST, response.request.headers, dict(results))
                        rep.finalizing_out()
            header_row = True

        # RUN INTRUDER
        i = Intruder(REPEATER_PATH_FILE, INTRUDER_PATH_FILE)
        i.run_intruder()

        today = datetime.now()
        today = today.strftime("%Y-%m-%d-%H-%M-%S")

        # RUN OBSERVATION MANAGER
        m = Analyzer(INTRUDER_PATH_FILE)
        OBS_PATH_FILE_CSV = OBS_PATH_DIR + PREFIX_TESTBED + str(today) + ".CSV"
        OBS_PATH_FILE_JSON = OBS_PATH_DIR + PREFIX_TESTBED + str(today) + ".json"
        m.evaluation(OBS_PATH_FILE_CSV, OBS_PATH_FILE_JSON)


wavsep_testbed_run()


