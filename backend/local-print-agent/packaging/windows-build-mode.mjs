// Development scaffolds are deliberately non-installable. Only the protected
// candidate workflow can supply the separately configured origin allowlist.
export function windowsBuildMode(args, env) {
  const modes = args.filter(arg => arg.startsWith('--mode='));
  if (args.length !== 1 || modes.length !== 1) throw new Error('Specify --mode=development or --mode=signed-candidate.');
  const mode = modes[0].slice(7);
  if (mode === 'development') return { mode, productionEligible: false, maintenanceOrigin: 'MSCQR_DEVELOPMENT_UPGRADES_DISABLED' };
  if (mode !== 'signed-candidate') throw new Error('Unsupported Windows installer build mode.');
  const parseOrigin = value => {
    if (!value || value !== value.trim()) throw new Error('An explicit approved HTTPS maintenance origin is required.');
    let url;
    try { url = new URL(value); } catch { throw new Error('Malformed maintenance origin.'); }
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/' ||
        value.includes('?') || value.includes('#') || /[\\\s]/.test(value)) throw new Error('Maintenance origin must be HTTPS without credentials, path, query or fragment.');
    // Reject even normalized-away paths and noncanonical host spellings.
    if (value !== url.origin && value !== `${url.origin}/`) throw new Error('Maintenance origin must be canonical.');
    return url.origin;
  };
  const maintenanceOrigin = parseOrigin(env.MSCQR_MAINTENANCE_API_ORIGIN);
  if (maintenanceOrigin !== parseOrigin(env.MSCQR_APPROVED_MAINTENANCE_API_ORIGIN)) throw new Error('Maintenance host is not the protected approved origin.');
  return { mode, productionEligible: true, maintenanceOrigin };
}
