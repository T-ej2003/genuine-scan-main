const withDot = (value) => (String(value).endsWith(".") ? String(value) : `${value}.`);

export const DEFAULT_REGIONAL_DNS_POLICY = {
  domainName: "mscqr.com",
  records: {
    defaultMumbai: {
      label: "Default/global * -> Mumbai ALB",
      setIdentifier: "default-mumbai",
      geoLocation: { CountryCode: "*" },
      albDnsName: "mscqr-mumbai-alb-1249752376.ap-south-1.elb.amazonaws.com",
      albHostedZoneId: "ZP97RAFLXTNZK",
    },
    africaCapeTown: {
      label: "Africa AF -> Cape Town ALB",
      setIdentifier: "africa-capetown",
      geoLocation: { ContinentCode: "AF" },
      albDnsName: "mscqr-capetown-alb-1730011881.af-south-1.elb.amazonaws.com",
      albHostedZoneId: "Z268VQBMOI5EKX",
    },
    europeLondon: {
      label: "Europe EU -> London ALB",
      setIdentifier: "europe-london",
      geoLocation: { ContinentCode: "EU" },
      albDnsName: "mscqr-alb-euw2-524835535.eu-west-2.elb.amazonaws.com",
      albHostedZoneId: "ZHURV8PSTC4K8",
    },
  },
};

export const SUPPORTED_REGIONAL_ROLLBACK_OPERATIONS = new Set([
  "rollback-europe",
  "rollback-africa",
  "restore-default-mumbai",
]);

export function regionalPolicyFromEnv(env = process.env) {
  const domainName = env.DOMAIN_NAME || DEFAULT_REGIONAL_DNS_POLICY.domainName;
  return {
    domainName,
    records: {
      defaultMumbai: {
        ...DEFAULT_REGIONAL_DNS_POLICY.records.defaultMumbai,
        setIdentifier: env.DEFAULT_SET_IDENTIFIER || DEFAULT_REGIONAL_DNS_POLICY.records.defaultMumbai.setIdentifier,
        albDnsName:
          env.DEFAULT_ALB_DNS_NAME ||
          env.MUMBAI_ALB_DNS_NAME ||
          DEFAULT_REGIONAL_DNS_POLICY.records.defaultMumbai.albDnsName,
        albHostedZoneId:
          env.DEFAULT_ALB_HOSTED_ZONE_ID ||
          env.MUMBAI_ALB_HOSTED_ZONE_ID ||
          DEFAULT_REGIONAL_DNS_POLICY.records.defaultMumbai.albHostedZoneId,
      },
      africaCapeTown: {
        ...DEFAULT_REGIONAL_DNS_POLICY.records.africaCapeTown,
        setIdentifier: env.AFRICA_SET_IDENTIFIER || DEFAULT_REGIONAL_DNS_POLICY.records.africaCapeTown.setIdentifier,
        albDnsName:
          env.AFRICA_ALB_DNS_NAME ||
          env.CAPETOWN_ALB_DNS_NAME ||
          DEFAULT_REGIONAL_DNS_POLICY.records.africaCapeTown.albDnsName,
        albHostedZoneId:
          env.AFRICA_ALB_HOSTED_ZONE_ID ||
          env.CAPETOWN_ALB_HOSTED_ZONE_ID ||
          DEFAULT_REGIONAL_DNS_POLICY.records.africaCapeTown.albHostedZoneId,
      },
      europeLondon: {
        ...DEFAULT_REGIONAL_DNS_POLICY.records.europeLondon,
        setIdentifier: env.EUROPE_SET_IDENTIFIER || DEFAULT_REGIONAL_DNS_POLICY.records.europeLondon.setIdentifier,
        albDnsName:
          env.EUROPE_ALB_DNS_NAME ||
          env.LONDON_ALB_DNS_NAME ||
          DEFAULT_REGIONAL_DNS_POLICY.records.europeLondon.albDnsName,
        albHostedZoneId:
          env.EUROPE_ALB_HOSTED_ZONE_ID ||
          env.LONDON_ALB_HOSTED_ZONE_ID ||
          DEFAULT_REGIONAL_DNS_POLICY.records.europeLondon.albHostedZoneId,
      },
    },
  };
}

export function aliasGeolocationARecord(domainName, record) {
  return {
    Name: withDot(domainName),
    Type: "A",
    SetIdentifier: record.setIdentifier,
    GeoLocation: record.geoLocation,
    AliasTarget: {
      HostedZoneId: record.albHostedZoneId,
      DNSName: withDot(record.albDnsName),
      EvaluateTargetHealth: true,
    },
  };
}

const change = (action, recordSet) => ({ Action: action, ResourceRecordSet: recordSet });

export function buildRegionalRollbackPlan({ operation, policy = DEFAULT_REGIONAL_DNS_POLICY }) {
  if (!SUPPORTED_REGIONAL_ROLLBACK_OPERATIONS.has(operation)) {
    throw new Error(`Unsupported operation: ${operation}`);
  }

  const defaultMumbai = aliasGeolocationARecord(policy.domainName, policy.records.defaultMumbai);
  const africaCapeTown = aliasGeolocationARecord(policy.domainName, policy.records.africaCapeTown);
  const europeLondon = aliasGeolocationARecord(policy.domainName, policy.records.europeLondon);

  const plans = {
    "rollback-europe": {
      target: policy.records.europeLondon,
      cutover: [change("DELETE", europeLondon)],
      rollback: [change("CREATE", europeLondon)],
      summary: "Delete only the Europe geolocation route europe-london; Africa and default Mumbai are preserved.",
    },
    "rollback-africa": {
      target: policy.records.africaCapeTown,
      cutover: [change("DELETE", africaCapeTown)],
      rollback: [change("CREATE", africaCapeTown)],
      summary: "Delete only the Africa geolocation route africa-capetown; Europe and default Mumbai are preserved.",
    },
    "restore-default-mumbai": {
      target: policy.records.defaultMumbai,
      cutover: [change("UPSERT", defaultMumbai)],
      rollback: [change("DELETE", defaultMumbai)],
      summary: "Restore only the default/global Mumbai geolocation route; Africa and Europe are preserved.",
    },
  };

  const plan = plans[operation];
  return {
    operation,
    targetSetIdentifier: plan.target.setIdentifier,
    cutoverBatch: {
      Comment: `MSCQR PLAN ONLY: ${operation} for current three-region geolocation DNS policy`,
      Changes: plan.cutover,
    },
    rollbackBatch: {
      Comment: `MSCQR PLAN ONLY inverse batch for ${operation}; review before any approved apply`,
      Changes: plan.rollback,
    },
    summary: plan.summary,
  };
}

export function route53BatchChangedSetIdentifiers(batch) {
  return (batch.Changes || [])
    .map((item) => item?.ResourceRecordSet?.SetIdentifier)
    .filter(Boolean);
}

export function validateApprovedRegionalRollbackBatch(batch, { requireApproval = true, env = process.env } = {}) {
  const findings = [];
  if (requireApproval && env.APPROVED_ROUTE53_ROLLBACK !== "true") {
    findings.push("APPROVED_ROUTE53_ROLLBACK=true is required before Route 53 rollback apply.");
  }
  if (!batch || !Array.isArray(batch.Changes) || batch.Changes.length === 0) {
    findings.push("CHANGE_BATCH_JSON must contain a non-empty Changes array.");
    return findings;
  }

  for (const [index, item] of batch.Changes.entries()) {
    const action = item?.Action;
    const rrset = item?.ResourceRecordSet;
    const prefix = `Changes[${index}]`;
    if (!["CREATE", "UPSERT", "DELETE"].includes(action)) {
      findings.push(`${prefix} has unsupported Action ${action || "<missing>"}.`);
    }
    if (!rrset) {
      findings.push(`${prefix} is missing ResourceRecordSet.`);
      continue;
    }

    const type = rrset.Type;
    const name = String(rrset.Name || "");
    const protectedDelete =
      action === "DELETE" &&
      (["MX", "TXT", "NS", "SOA"].includes(type) || (type === "CNAME" && name.toLowerCase() === "www.mscqr.com."));
    if (protectedDelete) {
      findings.push(`${prefix} refuses deletion of protected ${type} record ${name || "<unnamed>"}.`);
    }
    if (type !== "A") {
      findings.push(`${prefix} must be a Route 53 geolocation A record; found ${type || "<missing>"}.`);
      continue;
    }
    if (!rrset.SetIdentifier) {
      findings.push(`${prefix} is missing SetIdentifier.`);
    }
    if (!rrset.GeoLocation || typeof rrset.GeoLocation !== "object") {
      findings.push(`${prefix} is missing GeoLocation.`);
    }
    if (!rrset.AliasTarget?.HostedZoneId || !rrset.AliasTarget?.DNSName) {
      findings.push(`${prefix} must use an ALB AliasTarget with HostedZoneId and DNSName.`);
    }
  }

  return findings;
}

export function evaluateRoute53RegionalPolicy(records, policy = DEFAULT_REGIONAL_DNS_POLICY) {
  const bySetIdentifier = new Map(
    records
      .filter((record) => record.Type === "A" && record.SetIdentifier)
      .map((record) => [record.SetIdentifier, record]),
  );
  return [
    evaluateOneRecord(bySetIdentifier, policy.domainName, policy.records.africaCapeTown),
    evaluateOneRecord(bySetIdentifier, policy.domainName, policy.records.europeLondon),
    evaluateOneRecord(bySetIdentifier, policy.domainName, policy.records.defaultMumbai),
  ];
}

function evaluateOneRecord(bySetIdentifier, domainName, expected) {
  const actual = bySetIdentifier.get(expected.setIdentifier);
  if (!actual) {
    return {
      check: `route53_${expected.setIdentifier}`,
      scope: expected.label,
      status: "FAIL",
      detail: "record missing",
    };
  }

  const expectedRecord = aliasGeolocationARecord(domainName, expected);
  const sameGeo = JSON.stringify(actual.GeoLocation || {}) === JSON.stringify(expectedRecord.GeoLocation);
  const sameTarget =
    String(actual.AliasTarget?.DNSName || "").toLowerCase() === expectedRecord.AliasTarget.DNSName.toLowerCase() &&
    String(actual.AliasTarget?.HostedZoneId || "") === expectedRecord.AliasTarget.HostedZoneId;
  if (!sameGeo || !sameTarget) {
    return {
      check: `route53_${expected.setIdentifier}`,
      scope: expected.label,
      status: "FAIL",
      detail: `expected ${JSON.stringify(expectedRecord.GeoLocation)} -> ${expectedRecord.AliasTarget.DNSName}`,
    };
  }
  return {
    check: `route53_${expected.setIdentifier}`,
    scope: expected.label,
    status: "PASS",
    detail: actual.AliasTarget.DNSName,
  };
}
