
from Oracle.Oracle import Oracle

oracle = Oracle('./results/analyzer.json','./results/oracle_results.json','SQLI')
oracle.execute()

