const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/;

const parseIpv4 = (value, label) => {
  const match = String(value || "").trim().match(IPV4);
  if (!match) throw new Error(`${label} must be an IPv4 CIDR.`);
  const octets = match.slice(1, 5).map(Number);
  const prefix = Number(match[5]);
  if (octets.some((octet) => octet > 255) || prefix > 32) throw new Error(`${label} is invalid.`);
  const address = octets.reduce((result, octet) => (result * 256) + octet, 0);
  const size = 2 ** (32 - prefix);
  const start = Math.floor(address / size) * size;
  return { start, end: start + size - 1, prefix, size };
};

const contains = (outer, inner) => inner.start >= outer.start && inner.end <= outer.end;
const addressIn = (network, value, label) => {
  const parsed = parseIpv4(`${value}/32`, label);
  return parsed.start >= network.start && parsed.start <= network.end;
};

export const validateDockerBridgeNetworkContract = ({ subnet, dynamicRange, gateway, frontendIp, trustedCidr, dynamicServiceCount = 1, prefix = "ASG" }) => {
  const names = {
    subnet: `${prefix}_APP_NETWORK_SUBNET`,
    range: `${prefix}_APP_NETWORK_IP_RANGE`,
    gateway: `${prefix}_APP_NETWORK_GATEWAY`,
    frontend: `${prefix}_FRONTEND_PROXY_IP`,
  };
  const network = parseIpv4(subnet, names.subnet);
  const range = parseIpv4(dynamicRange, names.range);
  if (!contains(network, range)) throw new Error(`${names.range} must be contained by ${names.subnet}.`);
  if (!addressIn(network, gateway, names.gateway)) throw new Error(`${names.gateway} must be contained by ${names.subnet}.`);
  const gatewayAddress = parseIpv4(`${gateway}/32`, names.gateway).start;
  if (gatewayAddress === network.start || gatewayAddress === network.end) throw new Error(`${names.gateway} cannot be the network or broadcast address.`);
  if (addressIn(range, gateway, names.gateway)) throw new Error(`${names.range} cannot contain ${names.gateway}.`);
  if (!addressIn(network, frontendIp, names.frontend)) throw new Error(`${names.frontend} must be contained by ${names.subnet}.`);
  const frontend = parseIpv4(`${frontendIp}/32`, names.frontend);
  if (frontend.start === network.start || frontend.start === network.end) throw new Error(`${names.frontend} cannot be the network or broadcast address.`);
  if (frontendIp === gateway) throw new Error(`${names.frontend} cannot equal ${names.gateway}.`);
  if (addressIn(range, frontendIp, names.frontend)) throw new Error(`${names.frontend} must be outside ${names.range}.`);
  if (String(trustedCidr || "").trim() !== `${frontendIp}/32`) throw new Error("CLIENT_IP_TRUSTED_NGINX_CIDRS must be the exact frontend /32.");
  const reservedInRange = new Set([network.start, network.end, gatewayAddress]
    .filter((address) => address >= range.start && address <= range.end)).size;
  const usableAddresses = range.size - reservedInRange;
  if (!Number.isInteger(dynamicServiceCount) || dynamicServiceCount < 1 || usableAddresses < dynamicServiceCount) {
    throw new Error(`${names.range} provides ${usableAddresses} usable address(es), but ${dynamicServiceCount} dynamic service address(es) are required.`);
  }
  return { network, range, gateway, usableAddresses };
};

export const validateAsgNetworkContract = (input) => validateDockerBridgeNetworkContract({ ...input, prefix: "ASG" });
