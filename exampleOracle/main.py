from pyswip import *

prolog = Prolog()

prolog.assertz("statusCode200(200)")
prolog.assertz("contentLengthExceed(1)")
prolog.assertz("timeDelayIsVerified(1)")

prolog.assertz("roleSQLI1(200,1,1) :- "
               "statusCode200(200),"
               "contentLengthExceed(1),"
               "timeDelayIsVerified(1)")

query1 = list(prolog.query("statusCode200(%s)" % (400)))
print(bool(query1))

query2 = list(prolog.query("roleSQLI1(%s,%s,%s)" % (200, 1, 1)))
print(bool(query2))


