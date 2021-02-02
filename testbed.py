import os
from Intruder.Intruder import Intruder
from Analyzer.Analyzer import Analyzer
from Oracle.Oracle import Oracle
from Repeater.Repeater import *
import csv
from datetime import datetime
from bs4 import BeautifulSoup

REPEATER_PATH_FILE = "testbed/results/repeater_"
INTRUDER_PATH_FILE = "testbed/results/intruder_"
OBS_PATH_DIR = r"testbed/results/"
PATH_TESTBED = r"C:testbed/"
FILE_NAME_TESTBED = "TestBed.csv"
PREFIX_TESTBED = "analyzer_"


def extract_form_fields(soup):
    "Turn a BeautifulSoup form in to a dict of fields and default values"
    fields = {}
    for input in soup.findAll('input'):
        # ignore submit/image with no name attribute
        if input['type'] in ('submit', 'image') and not 'name' in input:
            continue

        # single element nome/value fields
        if input['type'] in ('text', 'hidden', 'password', 'submit', 'image','search','email','url'):
            value = ''
            if 'value' in input:
                value = input['value']
            fields[input['name']] = value
            continue

        # checkboxes and radios
        if input['type'] in ('checkbox', 'radio'):
            value = ''
            if input.has_attr("checked"):
                if input.has_attr('value'):
                    value = input['value']
                else:
                    value = 'on'
            if 'name' in input and value:
                fields[input['name']] = value

            if not 'name' in input:
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
        is_multiple = select.has_key('multiple')
        selected_options = [
            option for option in options
            if option.has_key('selected')
        ]

        # If no select options, go with the first one
        if not selected_options and options:
            selected_options = [options[0]]

        if not is_multiple:
            assert(len(selected_options) < 2)
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


def build_testbed_results(oracle_json_file: str, testbed_csv: str):
    csv_out_path = 'testbed/results/testbed.csv'
    # OPEN ORACLE JSON
    with open(oracle_json_file, encoding='utf-8') as json_oracle_input:
        oracle_json_results = json.load(json_oracle_input)
    # OPEN TESTBED CSV
    csv_reader = csv.reader(open(testbed_csv), delimiter=';', quotechar='|')
    # SKIP HEADER ROW
    next(csv_reader)
    f = csv.writer(open(csv_out_path, "w", newline="", encoding='utf8'))
    row_header = ["ID_REQ_TESTBED", "ID_FUZZ", 'URL', "METHOD", "INJECTION_TYPE", "CONTEXT", "INJECTION POSITION",
                  "RESULTS TESTBED", "RESULTS GENERIC TESTING", "RESULTS"]
    f.writerow(row_header)
    row_matrix = []
    for id_fuzz in oracle_json_results:
        csv_row = next(csv_reader)
        results_generic_testing = list()
        for r in oracle_json_results[id_fuzz]["Results"]:
            for rule in r['Oracle']:
                rule_name = rule['rule']
                rule_name = rule_name.replace("%s", "")
                rule_name = rule_name.replace(",", "")
                rule_name = rule_name.replace("()", "")
                if rule_name not in results_generic_testing:
                    results_generic_testing.append(rule_name)
        id_req_testbed = csv_row[0]
        url = csv_row[4]
        method = csv_row[2]
        injection_type = csv_row[5]
        context = csv_row[6]
        injection_position = csv_row[7]
        results_testbed = csv_row[8]
        if len(results_generic_testing) == 0:
            testbed_flag = 'FAILED'
        else:
            testbed_flag = 'SUCCESS'

        row_matrix.append(
            [id_req_testbed, id_fuzz, url, method, injection_type, context, injection_position, results_testbed,
             ','.join(results_generic_testing), testbed_flag])

    # WRITE ON FILE
    for r in row_matrix:
        f.writerow(r)


def wavsep_testbed_run():
    # CREATE A SESSION
    s = Session()
    flag_init_session = True
    today = datetime.now()
    today = today.strftime("%Y-%m-%d_%H_%M_%S")
    with open(PATH_TESTBED + FILE_NAME_TESTBED, newline='') as csv_file:
        reader = csv.reader(csv_file, delimiter=';', quotechar='|')
        header_row = False
        rep = Repeater(REPEATER_PATH_FILE + str(today) + ".json", False)
        for row in reader:
            if header_row:
                method = row[2]
                base_url = row[3]
                url = row[4]
                injection_type = row[5]

                full_url = base_url + url
                if flag_init_session:
                    init_session(s, full_url)
                    flag_init_session = False

                ###########################
                # RUN REPEATER
                r = Request('GET', url=full_url, headers=dict(), data=dict())
                prepped = s.prepare_request(r)
                response = s.send(prepped)

                if method == "GET":
                    rep.setting_request(method, r.url, dict(response.request.headers), dict(), injection_type)
                    rep.finalizing_out()
                else:
                    dir_name = os.path.dirname(full_url)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = soup.find_all('form')
                    for f in forms:
                        results = extract_form_fields(f)
                        if injection_type == 'PT/LFI':
                            rep.setting_request(method, full_url, dict(response.request.headers), dict(results),
                                                injection_type)
                        else:
                            if 'http://' not in f['action']:
                                url_post = dir_name + '/' + f['action']
                            else:
                                url_post = f['action']
                            rep.setting_request(method, url_post, dict(response.request.headers), dict(results),
                                                injection_type)
                        rep.finalizing_out()
                        break
            header_row = True

        # RUN INTRUDER
        i = Intruder(REPEATER_PATH_FILE + str(today) + ".json", INTRUDER_PATH_FILE + str(today) + ".json")
        i.execute()

        # RUN ANALYZER
        m = Analyzer(INTRUDER_PATH_FILE + str(today) + ".json", REPEATER_PATH_FILE + str(today) + ".json")
        analyzer_path_file_csv = OBS_PATH_DIR + PREFIX_TESTBED + str(today) + ".CSV"
        analyzer_path_file_json = OBS_PATH_DIR + PREFIX_TESTBED + str(today) + ".json"
        m.evaluation(analyzer_path_file_csv, analyzer_path_file_json)

        oracle_path_file = 'testbed/results/oracle_' + str(today) + ".json"
        # RUN ORACLE
        o = Oracle(analyzer_path_file_json, oracle_path_file)
        o.execute()
        build_testbed_results(oracle_path_file, PATH_TESTBED + FILE_NAME_TESTBED)


wavsep_testbed_run()
