#! VULNERABLE cert-renewer — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant renew irreversible

let raw = fetch<web>
commit { renew(raw) }  # tainted -> tool: REJECTED
