#!/bin/sh
# Configure Postfix as a deliberate OPEN RELAY, then run it in the foreground.
#
# The three lines that make it an open relay are mynetworks = 0.0.0.0/0 plus the
# relay/recipient restrictions ending in "permit": together they let any client
# hand off mail for any external recipient with no authentication. This is the
# classic misconfiguration HEAVEN's relay probe is meant to catch.
set -e

myhostname="relay.heaven.local"

postconf -e "myhostname = ${myhostname}"
postconf -e "mydomain = heaven.local"
postconf -e "myorigin = \$mydomain"
postconf -e "inet_interfaces = all"
postconf -e "inet_protocols = ipv4"

# Log to stdout so `docker logs` shows the SMTP transactions (Postfix 3.4+),
# instead of needing a syslog daemon inside the container.
postconf -e "maillog_file = /dev/stdout"

# ── the misconfiguration: a wide-open relay ──────────────────────────────────
# The restriction lists look perfectly normal (they still end in a reject, so
# Postfix's own open-relay safety check is satisfied and smtpd starts). The bug
# is a single over-broad line: mynetworks trusts the ENTIRE internet, so
# permit_mynetworks matches every client and short-circuits before the reject is
# ever reached. This is exactly how real open relays happen in the wild.
postconf -e "mynetworks = 0.0.0.0/0"
postconf -e "smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination"
postconf -e "smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination"

# No opportunistic TLS advertised — inbound mail is cleartext (also detected).
postconf -e "smtpd_tls_security_level = none"

# VRFY stays enabled (default) but Postfix answers 252 "cannot verify" for
# valid addresses, so it does NOT actually disclose which mailboxes exist; the
# open relay above is the intended finding.

newaliases 2>/dev/null || true

echo "[heaven-lab] Postfix open-relay lab starting on :25 (${myhostname})"
exec /usr/sbin/postfix start-fg
