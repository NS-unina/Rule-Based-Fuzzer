

"""prolog = Prolog()

prolog.consult("knowledge_base.pl")

query2 = list(prolog.query("ruleSQLI2(%s,%s,%s,%s)" % (200, 0, 0, 0)))
print(bool(query2))"""
from Oracle.Oracle import Oracle

oracle = Oracle('../results/observer.json')
oracle.execute()

