import json

with open('config/fuzz_list.json', encoding='utf-8') as json_file:
    fuzz_list = json.load(json_file)

# INIT OBSERVATION
dict_observation = dict()
for item in fuzz_list["fuzzList"]:
    dict_observation.update({item["payload"]: []})

print(dict_observation)



"""number_of_placeholder = 3
parameters_fuzz_dict = list()
# DA DICT A LIST PER POTERLO MODIFICARE
parameters_fuzz_dict =[['category', 'Accessories', True, 'URL'], [' test', 'test', True, 'URL'], ['TrackingId', 'dhDVrBsJQ2XifTSY', False, 'Cookie'], [' session', 'pL2GjS76IKrgJPrlKvfZN5fgHQKLhAkS', True, 'Cookie']]

lock = 0
count = 0
y = 0
json_dict = json.loads('{"Requests": []}')
json_req = json_dict["Requests"]
param_url = ""
param_cookie = ""
for i in range(0, number_of_placeholder):  # 1
    for j in range(0, len(fuzz_list["fuzzList"])):  # 0 - 31    (A,B,C,D)
        fuzz_dict = fuzz_list["fuzzList"][j]
        for k in parameters_fuzz_dict:
            value_param = k[1]
            if lock != 1:
                if k[2] is True:
                    prev = count
                    value_param = fuzz_dict["payload"]
                    lock = 1
            if k[3] == "URL":
                if param_url == "":
                    param_url = param_url + k[0] + "=" + value_param
                else:
                    param_url = param_url + "&" + k[0] + "=" + value_param
            else:
                if param_cookie == "":
                    param_cookie = param_cookie + k[0] + "=" + value_param
                else:
                    param_cookie = param_cookie + ";" + k[0] + "=" + value_param
            count += 1

        json_req.append({"index": y, "URL": "https://test.it", "method": "GET", "param": param_url, "cookie": param_cookie,"observation": [fuzz_dict]})
        param_url = ""
        param_cookie = ""
        y += 1
        lock = 0
        count = 0
    parameters_fuzz_dict[prev][2] = False

app_json = json.dumps(json_dict)
print(app_json)"""

