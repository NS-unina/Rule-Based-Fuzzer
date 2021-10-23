# Rule-Based Fuzzer
by Ciro Brandi.

Rule-Based fuzzer is a fuzzer that allows you to identify anomalies on a web application. This technique is implemented by a blackbox fuzzer allowing to identify anomalies of the type: SQLi, XSS, Path traversal and LFI.
# Installation
Install the packages using the command:
```bash 
pip install -r requirements.txt
```
Also you need to install Pyswig: https://www.swi-prolog.org/
# Modules
The repeater intercepts the desired request, placing the placeholders in the chosen parameters, producing in output a JSON file containing: HTTP request, HTTP response, Placeholder Request.
Repeater:
```bash 
main_repeater.py --url=<url_to_intercept> --output_file_path=<name_output_file.json>
```
The intruder sends a payload list to the target application, retrieving its HTTP response. The module takes the repeater's output file as input and performs a sniper attack on each placeholder placed by the repeater. The generated output file is a list of fuzzing sessions.
Intruder:
```bash 
main_intruder.py --repeater_file_path=<repeater_file_name> --out_file_path=<name_output_file.json>
```
the Analyzer analyzes the intruder's output file to make observations on the HTTP responses resulting from a sniper attack.
Analyzer:
```bash 
main_analyzer.py --intruder_file_path=<intruder_file_name> --repeater_file_path=<repeater_file_name> --analyzer_file_path=<analyzer_output_file>
```
The oracle identifies if in the observations made by the analyzer there is an anomaly in the response.
Oracle:
```bash 
main_oracle.py --anaylzer_file_path=<anaylzer_file_path>, --oracle_file_path=<oracle_output_file_path>, oracle_file_path_csv=<oracle_output_file_path>
```
To use all modules consecutively run:
```bash 
generic_testing_run.py --url_intercept=<url_intercept> --repeater_file_path=<repeater_file_path> intruder_file_path=<intruder_file_path>, <analyzer_file_path_csv>, <analyzer_file_path_json>,
        oracle_file_path=<oracle_file_path>, oracle_file_path_csv=<oracle_file_path_csv>
```
Example
```bash
generic_testing_run.py http://testphp.vulnweb.com results/repeater.json results/intruder.json results/observer.csv results/observer.json
```
To use generic testing on the testbed run:
```bash
testbed.py
```
