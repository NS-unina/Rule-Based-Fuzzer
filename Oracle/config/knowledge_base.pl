/* ##### CONCEPT ##### */
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
    ruleSQLI1(X, Y, Z, W) :- statusCode500(X),payloadIsReflected(Y),notValidContentLength(Z),timeDelayIsVerified(W).
    /* rule 2 [RULE 5 EXCEL]*/
    ruleSQLI2(X, Y, Z, W) :- statusCode200(X),payloadIsReflected(Y),notValidContentLength(Z),timeDelayIsVerified(W).
    /* rule 3 [RULE 6,7,8 EXCEL]*/
    ruleSQLI3(X, Y, Z, W) :- statusCode200(X),payloadIsReflected(Y),validContentLength(Z),timeDelayIsNotVerified(W).
    /* rule 4 [RULE 10 EXCEL]*/
    ruleSQLI4(X, Y, Z, W) :- statusCode200(X),payloadIsNotReflected(Y),validContentLength(Z),timeDelayIsVerified(W).
    /* RULE TUNING */
    ruleSQLI5(X,Y,Z,W):- statusCode500(X),payloadIsReflected(Y),validContentLength(Z),timeDelayIsNotVerified(W).
    ruleSQLI6(X,Y,Z,W):- statusCode200(X),payloadIsNotReflected(Y),notValidContentLength(Z),timeDelayIsNotVerified(W).
    ruleSQLI7(X,Y,Z,W):- statusCode200(X),payloadIsNotReflected(Y),notValidContentLength(Z),timeDelayIsVerified(W).

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
    ruleCI1(X, Y, Z, W) :- statusCode200(X),payloadIsReflected(Y),validContentLength(Z),timeDelayIsNotVerified(W).
    /* rule 2 [RULE 12 EXCEL] */
    ruleCI2(X, Y, Z, W) :- statusCode200(X),payloadIsNotReflected(Y),validContentLength(Z),timeDelayIsVerified(W).

    ciInjection(X):-
        X = ruleCI1(200, 1, 0, 0);
        X = ruleCI2(200, 0, 0, 1).

/* ##### Role PT ##### */
    /* rule 1 [RULE 13 EXCEL] */
     rulePT1(X, Y, Z, W) :- statusCode400(X),payloadIsReflected(Y),validContentLength(Z),timeDelayIsNotVerified(W).
    /* rule 2 [RULE 14 EXCEL] */
    rulePT2(X, Y, Z, W) :- statusCode200(X),payloadIsReflected(Y),notValidContentLength(Z),timeDelayIsNotVerified(W).
    /* TUNING RULE */
    rulePT3(X, Y, Z, W) :- statusCode404(X),payloadIsReflected(Y),validContentLength(Z),timeDelayIsNotVerified(W).
    rulePT4(X, Y, Z, W) :- statusCode200(X),payloadIsReflected(Y),validContentLength(Z),timeDelayIsNotVerified(W).
    rulePT5(X, Y, Z, W) :- statusCode500(X),payloadIsReflected(Y),validContentLength(Z),timeDelayIsNotVerified(W).
    rulePT6(X, Y, Z, W) :- statusCode200(X),payloadIsNotReflected(Y),notValidContentLength(Z),timeDelayIsNotVerified(W).
    rulePT7(X, Y, Z, W) :- statusCode200(X),payloadIsNotReflected(Y),notValidContentLength(Z),timeDelayIsVerified(W).

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
    ruleXSS1(X, Y, Z, W) :-
                statusCode200(X),
                payloadIsReflected(Y),
                validContentLength(Z),
                timeDelayIsNotVerified(W).

    xssInjection(X):-
        X = ruleXSS1(200, 1, 0, 0). 



/* #### Role CMDi ###### */