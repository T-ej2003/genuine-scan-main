// Source contract: hand-reviewed shape from `aws iam simulate-principal-policy --output json`.
// The AWS CLI response uses PascalCase member names; this fixture is intentionally
// independent of the parser implementation.
export default {
  EvaluationResults: [{
    EvalActionName: "lambda:UpdateFunctionConfiguration",
    EvalResourceName: "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker",
    EvalDecision: "allowed",
    MatchedStatements: [],
    MissingContextValues: [],
  }],
};
