export const ECR_POLICY_REGISTRY_ID = "368992683803";
export const ECR_POLICY_REPOSITORY_NAME = "mscqr-backend";
export const ECR_ALLOW_STATEMENT = Object.freeze({
  Sid: "AllowRuntimePull",
  Effect: "Allow",
  Principal: { AWS: "arn:aws:iam::368992683803:role/mscqr-ecs-execution-role" },
  Action: ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
  Resource: "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend",
});
export const ECR_DOCUMENTED_NO_RESOURCE_POLICY = Object.freeze({
  Version: "2008-10-17",
  Statement: [{
    Sid: "allow public pull",
    Effect: "Allow",
    Principal: "*",
    Action: ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
  }],
});

const omit = (value, ...keys) => Object.fromEntries(Object.entries(value).filter(([key]) => !keys.includes(key)));
const policy = (statement) => ({ Version: "2012-10-17", Statement: [statement] });

export const VALID_ECR_REPOSITORY_POLICIES = Object.freeze([
  ECR_DOCUMENTED_NO_RESOURCE_POLICY,
  policy(ECR_ALLOW_STATEMENT),
  policy({ Effect: "Deny", Principal: "*", Action: "ecr:BatchGetImage", Resource: "*" }),
  policy({ Effect: "Allow", Principal: { AWS: ["arn:aws:iam::368992683803:root"] }, Action: ["ecr:BatchGetImage"], Resource: ["*"], Condition: { StringEquals: { "aws:PrincipalAccount": "368992683803" } } }),
  policy({ Effect: "Deny", NotPrincipal: { Service: "ecs-tasks.amazonaws.com" }, NotAction: "ecr:GetDownloadUrlForLayer", NotResource: "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-worker" }),
  { Version: "2012-10-17", Statement: [ECR_ALLOW_STATEMENT, { Effect: "Deny", Principal: "*", Action: "ecr:PutImage", Resource: "*" }] },
]);

export const MALFORMED_ECR_REPOSITORY_POLICIES = Object.freeze([
  ["null policy", null], ["array policy", []], ["string policy", "policy"], ["numeric policy", 1], ["empty policy", {}],
  ["missing Statement", { Version: "2012-10-17" }], ["empty Statement", { Version: "2012-10-17", Statement: [] }],
  ["null Statement", { Version: "2012-10-17", Statement: null }], ["object Statement", { Version: "2012-10-17", Statement: {} }],
  ["string Statement", { Version: "2012-10-17", Statement: "statement" }],
  ...[null, true, false, 0, 1, "", "statement", [], {}].map((statement) => [`invalid Statement entry ${JSON.stringify(statement)}`, policy(statement)]),
  ["mixed valid and null", { Version: "2012-10-17", Statement: [ECR_ALLOW_STATEMENT, null] }],
  ["mixed valid and primitive", { Version: "2012-10-17", Statement: [ECR_ALLOW_STATEMENT, 1] }],
  ["nested Statement array", policy([ECR_ALLOW_STATEMENT])],
  ["missing Principal", policy(omit(ECR_ALLOW_STATEMENT, "Principal"))],
  ["missing Action", policy(omit(ECR_ALLOW_STATEMENT, "Action"))],
  ["missing Effect", policy(omit(ECR_ALLOW_STATEMENT, "Effect"))],
  ["Principal and NotPrincipal", policy({ ...ECR_ALLOW_STATEMENT, NotPrincipal: "*" })],
  ["Action and NotAction", policy({ ...ECR_ALLOW_STATEMENT, NotAction: "ecr:GetDownloadUrlForLayer" })],
  ["Resource and NotResource", policy({ ...ECR_ALLOW_STATEMENT, NotResource: "*" })],
  ...[null, 1, [], {}, { AWS: [] }, { Unknown: "*" }].map((Principal) => [`invalid Principal ${JSON.stringify(Principal)}`, policy({ ...ECR_ALLOW_STATEMENT, Principal })]),
  ...[null, [], ["ecr:BatchGetImage", null], {}].map((Action) => [`invalid Action ${JSON.stringify(Action)}`, policy({ ...ECR_ALLOW_STATEMENT, Action })]),
  ...[null, [], ["*", null], {}].map((Resource) => [`invalid Resource ${JSON.stringify(Resource)}`, policy({ ...ECR_ALLOW_STATEMENT, Resource })]),
  ...[null, [], ["*", null], {}].map((NotResource) => [`invalid NotResource ${JSON.stringify(NotResource)}`, policy({ ...omit(ECR_ALLOW_STATEMENT, "Resource"), NotResource })]),
  ...[null, true, 1, {}, [], "Permit"].map((Effect) => [`invalid Effect ${JSON.stringify(Effect)}`, policy({ ...ECR_ALLOW_STATEMENT, Effect })]),
  ...[null, [], "condition", { StringEquals: null }, { StringEquals: { "aws:PrincipalAccount": [["368992683803"]] } }].map((Condition) => [`invalid Condition ${JSON.stringify(Condition)}`, policy({ ...ECR_ALLOW_STATEMENT, Condition })]),
  ...[null, 1, {}, [], ""].map((Sid) => [`invalid Sid ${JSON.stringify(Sid)}`, policy({ ...ECR_ALLOW_STATEMENT, Sid })]),
  ["unknown statement field", policy({ ...ECR_ALLOW_STATEMENT, Unknown: true })],
]);
