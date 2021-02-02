/* ##### ATOM CONCEPT ##### */
    /* status code */
    statusCode200(200).
    statusCode400(400).
    statusCode500(500).
    statusCode404(404).

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
    ruleSQLI1(500, 1, 1, 1) :- statusCode500(500),payloadIsReflected(1),notValidContentLength(1),timeDelayIsVerified(1).
    /* rule 2 [RULE 5 EXCEL]*/
    ruleSQLI2(200, 1, 1, 1) :- statusCode200(200),payloadIsReflected(1),notValidContentLength(1),timeDelayIsVerified(1).
    /* rule 3 [RULE 6,7,8 EXCEL]*/
    ruleSQLI3(200, 1, 0, 0) :- statusCode200(200),payloadIsReflected(1),validContentLength(0),timeDelayIsNotVerified(0).
    /* rule 4 [RULE 10 EXCEL]*/
    ruleSQLI4(200, 0, 0, 1) :- statusCode200(200),payloadIsNotReflected(0),validContentLength(0),timeDelayIsVerified(1).
    /* RULE TUNING */
    ruleSQLI5(500,1,0,0):- statusCode500(500),payloadIsReflected(1),validContentLength(0),timeDelayIsNotVerified(0).
    ruleSQLI6(200,0,1,0):- statusCode200(200),payloadIsNotReflected(0),notValidContentLength(1),timeDelayIsNotVerified(0).
    ruleSQLI7(200,0,1,1):- statusCode200(200),payloadIsNotReflected(0),notValidContentLength(1),timeDelayIsVerified(1).

    sqlInjection(X):-
        X = ruleSQLI1(500, 1, 1, 1);
        X = ruleSQLI2(200, 1, 1, 1);
        X = ruleSQLI3(200, 1, 0, 0);
        X = ruleSQLI4(200, 0, 0, 1);
        X = ruleSQLI5(500, 1, 0, 0);
        X = ruleSQLI6(200, 0, 1, 0);
        X = ruleSQLI7(200, 0, 1, 1).

/* ##### Rule CI ##### */
    /* rule 1 [RULE 11 EXCEL] */
    ruleCI1(200, 1, 0, 0) :- statusCode200(200),payloadIsReflected(1),validContentLength(0),timeDelayIsNotVerified(0).
    /* rule 2 [RULE 12 EXCEL] */
    ruleCI2(200, 0, 0, 1) :- statusCode200(200),payloadIsNotReflected(0),validContentLength(0),timeDelayIsVerified(1).

    ciInjection(X):-
        X = ruleCI1(200, 1, 0, 0);
        X = ruleCI2(200, 0, 0, 1).

/* ##### Role PT ##### */
    /* rule 1 [RULE 13 EXCEL] */
     rulePT1(400, 1, 0, 0) :- statusCode400(400),payloadIsReflected(1),validContentLength(0),timeDelayIsNotVerified(0).
    /* rule 2 [RULE 14 EXCEL] */
    rulePT2(200, 1, 1, 0) :- statusCode200(200),payloadIsReflected(1),notValidContentLength(1),timeDelayIsNotVerified(0).
    /* TUNING RULE */
    rulePT3(404, 1, 0, 0) :- statusCode404(404),payloadIsReflected(1),validContentLength(0),timeDelayIsNotVerified(0).
    rulePT4(200, 1, 0, 0) :- statusCode200(200),payloadIsReflected(1),validContentLength(0),timeDelayIsNotVerified(0).
    rulePT5(500, 1, 0, 0) :- statusCode500(500),payloadIsReflected(1),validContentLength(0),timeDelayIsNotVerified(0).
    rulePT6(200, 0, 1, 0) :- statusCode200(200),payloadIsNotReflected(0),notValidContentLength(1),timeDelayIsNotVerified(0).
    rulePT7(200, 0, 1, 1) :- statusCode200(200),payloadIsNotReflected(0),notValidContentLength(1),timeDelayIsVerified(1).

    ptInjection(X):-
        X = rulePT1(400, 1, 0, 0);
        X = rulePT2(200, 1, 1, 0);
        X = rulePT3(404, 1, 0, 0);
        X = rulePT4(200, 1, 0, 0);
        X = rulePT5(500, 1, 0, 0);
        X = rulePT6(200, 0, 1, 0);
        X = rulePT7(200, 0, 1, 1).

/* ##### Role XXSR #####*/
    /* rule 1 [RULE 15 EXCEL] */
    ruleXSSR1(200, 1, 0, 0) :-
                statusCode200(200),
                payloadIsReflected(1),
                validContentLength(0),
                timeDelayIsNotVerified(0).

    xssInjection(X):-
        X = ruleXSSR1(200, 1, 0, 0).