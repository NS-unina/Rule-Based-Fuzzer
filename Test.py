import json

with open('config/fuzz_list.json', encoding='utf-8') as json_file:
    fuzz_list = json.load(json_file)
number_of_placeholder = 3
parameters_fuzz_dict = list()
# DA DICT A LIST PER POTERLO MODIFICARE
parameters_fuzz_dict =[['category', 'Accessories', True, 'URL'], [' test', 'test', True, 'URL'], ['TrackingId', 'dhDVrBsJQ2XifTSY', False, 'Cookie'], [' session', 'pL2GjS76IKrgJPrlKvfZN5fgHQKLhAkS', True, 'Cookie']]

lock = 0
couple_temp = ()
tmp_dict = dict()
count = 0
y = 0
for i in range(0, number_of_placeholder):  # 1
    for j in range(0, len(fuzz_list["fuzzList"])):  # 0 - 31    (A,B,C,D)
        fuzz_dict = fuzz_list["fuzzList"][j]
        for k in parameters_fuzz_dict:
            if lock != 1:
                if k[2] is True:
                    prev = count
                    couple_temp = couple_temp + (k[0], fuzz_dict["payload"], k[2], k[3])
                    lock = 1
                else:
                    couple_temp = couple_temp + (k[0], k[1], k[2], k[3])
            else:
                couple_temp = couple_temp + (k[0], k[1], False, k[3])
            count += 1
        tmp_dict[y] = couple_temp
        couple_temp = ()
        y += 1
        lock = 0
        count = 0
    parameters_fuzz_dict[prev][2] = False

print(tmp_dict)
