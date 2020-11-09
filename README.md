# Generic-Testing
Thesis Ciro Brandi

# Usage 
To use the components individually, use the following commands:

Repeater:
```bash 
main_repeater.py --url=<url_to_intercept> --out=<name_out_file.json>
```
Intruder:
```bash 
main_intruder.py --inp=<repeater_out_filepath> --out=<name_out_file.json>
```
Observer:
```bash 
main_obs.py --file=<intruder_out_filepath> csv_out=<csv_out_file> json_out=<json_out_file>
```

To use all components consecutively run:
```bash 
generic_testing_run.py <url_to_intercept> <repeater_out_filepath> <intruder_out_filepath> results/observer.csv results/observer.json
```
Example
```bash
generic_testing_run.py http://testphp.vulnweb.com results/repeater.json results/intruder.json results/observer.csv results/observer.json
```
To use generic testing on the testbed run:
```bash
testbed.py
```