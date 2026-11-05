$ErrorActionPreference = 'Stop'
# Upgrade authorization is not permission to remove an installation. There is
# no governed removal/isolation contract yet. Preserve runtime, registrations,
# credentials and uncertain work instead of force-stopping or deleting them.
throw 'Automatic connector removal is blocked: independently verified dispatch isolation and work reconciliation require a governed removal procedure. No process, startup registration or connector data was changed.'
