import os
import sys
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
PATH_TESTBED = r"./testbed/"
FILE_NAME_TESTBED = "TestBed.csv"
PREFIX_TESTBED = "analyzer_"


def extract_form_fields(soup):
    "Turn a BeautifulSoup form in to a dict of fields and default values"
    fields = {}
    for input in soup.findAll('inpldut'):
        # ignore submit/image with no name attribute
        if input['type'] in ('submit', 'image') and not 'name' in input:
            continue

        # single element nome/value fields
        if input['type'] in ('text', 'hidden', 'password', 'submit', 'image', 'search', 'email', 'url'):
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


def build_testbed_results(oracle_json_file: str, testbed_csv: str):
    true_positive = 0
    true_negative = 0
    false_positive = 0
    false_negative = 0

    csv_out_path = 'testbed/results/testbed.csv'
    # OPEN ORACLE CSV
    oracle_csv_results = csv.reader(open(oracle_json_file), delimiter=';', quotechar='|')
    # SKIP HEADER ROW
    next(oracle_csv_results)
    # OPEN TESTBED CSV
    csv_reader = csv.reader(open(testbed_csv), delimiter=';', quotechar='|')
    # SKIP HEADER ROW
    next(csv_reader)

    f = csv.writer(open(csv_out_path, "w", newline="", encoding='utf8'))
    row_header = ["ID_REQ_TESTBED", "ID_FUZZ", 'URL', "METHOD", "VULNERABILITY", "CONTEXT", "INJECTION POSITION",
                  "RESULTS TESTBED", "RULE ACTIVATED", "RESULTS ORACLE", "RESULTS", "SPECIFICITY"]
    f.writerow(row_header)

    row_matrix = []
    for oracle_csv_row in oracle_csv_results:
        csv_row = next(csv_reader)
        rule_activated = oracle_csv_row[1]
        oracle_results = oracle_csv_row[2]
        id_fuzz = oracle_csv_row[0]
        id_req_testbed = csv_row[0]
        url = csv_row[4]
        method = csv_row[2]
        vulnerability = csv_row[5]
        context = csv_row[6]
        injection_position = csv_row[7]
        results_testbed = csv_row[8]
        testbed_flag = 'FAILED'
        specificity = 0

        if vulnerability == "N/A" and len(oracle_results) == 0:
            testbed_flag = 'SUCCESS'
        else:
            for oracle_result in oracle_results.split(","):
                if vulnerability.lower() in oracle_result:
                    testbed_flag = 'SUCCESS'
                    specificity = specificity + 1
                else:
                    specificity = specificity - 0.1

        row_matrix.append(
            [id_req_testbed, id_fuzz, url, method, vulnerability, context, injection_position, results_testbed,
             rule_activated, oracle_results, testbed_flag, specificity])

        if vulnerability != 'N/A':
            if testbed_flag == 'SUCCESS':
                true_positive = true_positive + 1
            else:
                false_negative = false_negative + 1
        else:
            if len(oracle_results) == 0:
                true_negative = true_negative + 1
            else:
                if len(oracle_results) != 0:
                    false_positive = false_positive + 1

    # WRITE ON FILE
    for r in row_matrix:
        f.writerow(r)

    print("#### STATISTICS ####")
    print("TP: %s" % true_positive)
    print("TN: %s" % true_negative)
    print("FP: %s" % false_positive)
    print("FN: %s" % false_negative)
    print("Precision: %s" % (true_positive / (true_positive + false_positive)))
    print("Accuracy: %s" % (
            (true_positive + true_negative) / (true_positive + true_negative + false_positive + false_negative)))
    print("Recall: %s" % (
            true_positive / (true_positive + false_negative)))


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
                try:
                    r = Request('GET', url=full_url, headers=dict(), data=dict())
                    prepped = s.prepare_request(r)
                    response = s.send(prepped)

                    if method == "GET":
                        rep.setting_request(method, r.url, dict(response.request.headers), dict())
                        rep.finalizing_out()
                    else:
                        dir_name = os.path.dirname(full_url)
                        soup = BeautifulSoup(response.text, 'html.parser')
                        forms = soup.find_all('form')
                        for f in forms:
                            results = extract_form_fields(f)
                            if injection_type == 'PT/LFI':
                                rep.setting_request(method, full_url, dict(response.request.headers), dict(results))
                            else:
                                if f.get('action'):
                                    if 'http://' not in f['action']:
                                        url_post = dir_name + '/' + f['action']
                                    else:
                                        url_post = f['action']
                                    rep.setting_request(method, url_post, dict(response.request.headers), dict(results))
                            rep.finalizing_out()
                            break
                except Exception as err:
                    print("In testbed error")
                    print(err)
                    sys.exit("Exit")
                    print("Error on build request")
            header_row = True

        # RUN INTRUDER
        i = Intruder(REPEATER_PATH_FILE + str(today) + ".json", INTRUDER_PATH_FILE + str(today) + ".json")
        i.execute()
        # RUN ANALYZER
        m = Analyzer(INTRUDER_PATH_FILE + str(today) + ".json", REPEATER_PATH_FILE + str(today) + ".json")
        analyzer_path_file_json = OBS_PATH_DIR + PREFIX_TESTBED + str(today) + ".json"
        m.evaluation(analyzer_path_file_json)

        oracle_path_file_json = 'testbed/results/oracle_' + str(today) + ".json"
        oracle_path_file_csv = 'testbed/results/oracle_' + str(today) + ".csv"
        # RUN ORACLE
        o = Oracle(analyzer_path_file_json, oracle_path_file_json, oracle_path_file_csv)
        o.execute()
        build_testbed_results(oracle_path_file_csv, PATH_TESTBED + FILE_NAME_TESTBED)


wavsep_testbed_run()
#build_testbed_results('testbed/results/oracle_2021-02-27_13_56_29.csv', PATH_TESTBED + FILE_NAME_TESTBED)
