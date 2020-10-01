# Generic-Testing
Thesis Ciro Brandi

# Usage 
Repeater:
```bash 
main_repeater.py --url=<url_to_intercept> --out=<name_out_file.json>
```
Intruder:
```bash 
main_intruder.py --file=<repeater_out_filepath>
```
Observer:
```bash 
main_obs.py --file=<intruder_out_filepath>
```