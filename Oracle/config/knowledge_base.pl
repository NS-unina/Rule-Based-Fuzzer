/* ##### ATOM CONCEPT ##### */
    /* status code */
    statusCode200(200).
    statusCode400(400).
    statusCode500(500).

    /* content length */
    validContentLength(0).
    notValidContentLength(1).

    /* time delay*/
    timeDelayIsVerified(1).
    timeDelayIsNotVerified(0).

    /* keyword search */
    payloadIsReflected(1).
    payloadIsNotReflected(0).

/* ##### Rule SQLI ##### */

    /* rule 1 [RULE 3 EXCEL] */
    ruleSQLI1(500, 1, 1, 1) :-
                statusCode500(500),
                payloadIsReflected(1),
                notValidContentLength(1),
                timeDelayIsVerified(1),
                write('SQLI - RULE 1°: Anomaly Detected\n').
    /* rule 2 [RULE 5 EXCEL]*/
    ruleSQLI2(200, 1, 1, 1) :-
                statusCode200(200),
                payloadIsReflected(1),
                notValidContentLength(1),
                timeDelayIsVerified(1),
                write('SQLI - RULE 2°: Anomaly Detected\n').
    /* rule 3 [RULE 6,7,8 EXCEL]*/
    ruleSQLI3(200, 1, 1, 1) :-
                statusCode200(200),
                payloadIsReflected(1),
                validContentLength(0),
                timeDelayIsNotVerified(0),
                write('SQLI - RULE 3°: Anomaly Detected\n').
    /* rule 4 [RULE 10 EXCEL]*/
    ruleSQLI4(200, 1, 1, 1) :-
                statusCode200(200),
                payloadIsNotReflected(0),
                validContentLength(0),
                timeDelayIsVerified(1),
                write('SQLI - RULE 4°: Anomaly Detected\n').
/* ##### Rule CI ##### */
    /* rule 1 [RULE 11 EXCEL] */
    ruleCI1(200, 1, 0, 0) :-
                statusCode200(200),
                payloadIsReflected(1),
                validContentLength(0),
                timeDelayIsNotVerified(0),
                write('CI - RULE 1°: Anomaly Detected\n').
    /* rule 2 [RULE 12 EXCEL] */
    ruleCI2(200, 0, 0, 1) :-
                statusCode200(200),
                payloadIsNotReflected(0),
                validContentLength(0),
                timeDelayIsVerified(1),
                write('CI - RULE 2°: Anomaly Detected').
/* ##### Role PT ##### */
    /* rule 1 [RULE 13 EXCEL] */
     rulePT1(400, 1, 0, 0) :-
                statusCode400(400),
                payloadIsReflected(1),
                validContentLength(0),
                timeDelayIsNotVerified(0),
                write('PT - RULE 1°: Anomaly Detected\n').
    /* rule 2 [RULE 14 EXCEL] */
    rulePT2(200, 1, 1, 0) :-
                statusCode200(200),
                payloadIsReflected(1),
                notValidContentLength(1),
                timeDelayIsNotVerified(0),
                write('PT - RULE 2°: Anomaly Detected\n').
/* ##### Role XXSR #####*/
    /* rule 1 [RULE 15 EXCEL] */
    ruleXSSR1(200, 1, 0, 0) :-
                statusCode200(200),
                payloadIsReflected(1),
                validContentLength(0),
                timeDelayIsNotVerified(0),
                write('XSSR - RULE 1°: Anomaly Detected\n').