# Rule-Based Fuzzer
by Ciro Brandi.

Rule-Based fuzzer is a fuzzer that allows you to identify anomalies on a web application. This technique is implemented by a blackbox fuzzer allowing to identify anomalies of the type: SQLi, XSS, Path traversal and LFI.
# Installation
Install the packages using the command:
```bash 
pip install -r requirements.txt
```
Also you need to install Pyswig: https://www.swi-prolog.org/  
You can use the following guide to install it: 
https://wwu-pi.github.io/tutorials/lectures/lsp/010_install_swi_prolog.html  


# Modules
The repeater intercepts the desired request, placing the placeholders in the chosen parameters, producing in output a JSON file containing: HTTP request, HTTP response, Placeholder Request.
## Repeater   
The repeater is a mitmdump script that intercepts the http requests and places placeholders.   

```bash 
mitmdump -s repeater.py  -k -q
```  
Default values: 
- url: http://127.0.0.1:18080/wavsep 
- output: repeater.json  

### Run with options  
```bash
mitmdump -s repeater.py  -k -q --set url=https://127.0.0.1:8443/ --set output=owasp-cmd.json
```
## Intruder  
The intruder sends a payload list to the target application, retrieving its HTTP response. The module takes the repeater's output file as input and performs a sniper attack on each placeholder placed by the repeater. The generated output file is a list of fuzzing sessions.
Intruder:
```bash 
intruder.py --repeater=<repeater_file_name> --output=<name_output_file.json> (--verbose=True)
```   

## Analyzer  
the Analyzer analyzes the intruder's output file to make observations on the HTTP responses resulting from a sniper attack.
Analyzer:
```bash 
analyzer.py --intruder=<intruder_file_name> --repeater=<repeater_file_name> --analyzer=<analyzer_output_file>
```


## Oracle 
The oracle identifies if in the observations made by the analyzer there is an anomaly in the response.
Oracle:
```bash 
oracle.py --analyzer=<anaylzer_file_path>, --oracle=<oracle_output_file_path> --csv=<oracle_output_file_path>
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


### Testbed usage 
Run `docker-compose up` the first time and install wordpress. 
Then you can run the attacks to reproduce the experiments.   
``` 
cd vulnenv 
docker-compose up 
``` 

Wavsep and wordpress will be run on the following urls:   
* http://127.0.0.1:8000/wavsep/ . 
* http://127.0.0.1:8080/     


To configure the environments:
- Go to `http://127.0.0.1:8080/wavsep/wavsep-install/install.jsp` and put the following data:
  - username: `root` 
  - password `pass`
  - host: `wavsep-db`

  For Wordpress, put

python testbed.py




#### Data acquisition  
``` 
python main_repeater.py --url j
``` 