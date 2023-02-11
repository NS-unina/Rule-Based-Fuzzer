import json
LIMIT = 10

import csv

header = ['id_fuzz', 'url', 'payload', 'method', 'resp_status_code', 'resp_content_length', 'resp_time_elapsed', 'type_payload', 'payload',
        'observation_status_code', 'observation_search_file_not_found', 'observation_search_no_such_file', 'observation_search_uid',
        'observation_search_gid', 'observation_search_groups', 'observation_search_gpermission_denied', 'observation_search_whoami',
        'observation_search_root', 'observation_daemon', 'observation_error', 'observation_exception', 'observation_illegal',
        'observation_invalid', 'observation_fail', 'observation_stack', 'observation_access', 'observation_directory', 'observation_not_found',
        'observation_unknown', 'observation_ODBC', 'observation_SQL', 'observation_quotation_mark', 'observation_syntax', 'observation_ORA',
        'observation_111111', 'observation_time_delay', 'observation_content_length']





with open('owasp-cmd.json') as f:
    fs = json.load(f)
    with open('output.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for k, v in fs.items():
            results = v['Results']
            for r in results:
                req     = r['Request']
                resp    = r['Response']
                url     = req['url']
                payload = req['payload']
                method  = req['method']

                resp_status_code          = resp['status_code']
                resp_content_length       = resp['content_length']
                resp_time_elapsed         = resp['time_elapsed']

                type_payload              = r['TypePayload']
                payload                   = r['Payload']
                o               = r['Observation']
                observation_status_code   = o['StatusCode']
                observation_search_file_not_found = o['SearchKeyword']['File not found']
                observation_search_no_such_file = o['SearchKeyword']['No such file']
                observation_search_uid  = o['SearchKeyword']['uid=']
                observation_search_gid  = o['SearchKeyword']['gid=']
                observation_search_groups = o['SearchKeyword']['groups=']
                observation_search_gpermission_denied = o['SearchKeyword']['Permission denied']
                observation_search_whoami           = o['SearchKeyword']['whoami']
                observation_search_root          = o['SearchKeyword']['root:']
                observation_daemon = o['SearchKeyword']['daemon:']
                observation_error = o['SearchKeyword']['error']
                observation_exception = o['SearchKeyword']['exception']
                observation_illegal = o['SearchKeyword']['illegal']
                observation_invalid = o['SearchKeyword']['invalid']
                observation_fail = o['SearchKeyword']['fail']
                observation_stack = o['SearchKeyword']['stack']
                observation_access = o['SearchKeyword']['access']
                observation_directory = o['SearchKeyword']['directory']
                observation_not_found = o['SearchKeyword']['not found']
                observation_unknown = o['SearchKeyword']['unknown']
                observation_ODBC = o['SearchKeyword']['ODBC']
                observation_SQL = o['SearchKeyword']['SQL']
                observation_quotation_mark = o['SearchKeyword']['quotation mark']
                observation_syntax = o['SearchKeyword']['syntax']
                observation_ORA = o['SearchKeyword']['ORA-']
                observation_111111 = o['SearchKeyword']['111111']
                observation_time_delay = o['TimeDelay']
                observation_content_length = o['ContentLength']



                writer.writerow([k, url,payload,method,resp_status_code,resp_content_length,resp_time_elapsed,type_payload,payload,observation_status_code,observation_search_file_not_found,observation_search_no_such_file,observation_search_uid,observation_search_gid,observation_search_groups,observation_search_gpermission_denied,observation_search_whoami,observation_search_root,observation_daemon,observation_error,observation_exception,observation_illegal,observation_invalid,observation_fail,observation_stack,observation_access,observation_directory,observation_not_found,observation_unknown,observation_ODBC,observation_SQL,observation_quotation_mark,observation_syntax,observation_ORA,observation_111111,observation_time_delay,observation_content_length])

            

