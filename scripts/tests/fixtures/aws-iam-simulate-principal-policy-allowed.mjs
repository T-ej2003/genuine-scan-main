// Source contract: hand-reviewed shape from `aws iam simulate-principal-policy --output json`.
// The AWS CLI response uses PascalCase member names; this fixture is intentionally
// independent of the parser implementation.
import { STAGE_B } from "../../aws/production-green-stage-b-contract.mjs";

export default {
  EvaluationResults: [{
    EvalActionName: "lambda:UpdateFunctionConfiguration",
    EvalResourceName: STAGE_B.brokerFunctionArn,
    EvalDecision: "allowed",
    MatchedStatements: [],
    MissingContextValues: [],
  }],
};
