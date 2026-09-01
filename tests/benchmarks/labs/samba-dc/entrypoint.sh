#!/bin/bash
# Provision a Samba AD Domain Controller on first boot, then run it in the
# foreground. Idempotent: a re-created container with a fresh volume provisions
# again; an existing provision is reused.
set -euo pipefail

REALM="HEAVEN.LOCAL"
DOMAIN="HEAVEN"
ADMINPASS="Passw0rd!2026#Aegis"

if [ ! -f /var/lib/samba/.heaven-provisioned ]; then
    # Samba refuses to provision on top of the packaged default smb.conf.
    rm -f /etc/samba/smb.conf

    # Provision the domain. "ldap server require strong auth = no" lets a plain
    # LDAP SIMPLE bind work (used by HEAVEN's LDAP-based AD checks); it does not
    # affect the Kerberos or coercion probes exercised by the benchmark.
    samba-tool domain provision \
        --realm="${REALM}" \
        --domain="${DOMAIN}" \
        --server-role=dc \
        --dns-backend=SAMBA_INTERNAL \
        --adminpass="${ADMINPASS}" \
        --option="ldap server require strong auth = no"

    # Seed unprivileged accounts. These give the Kerberos enumeration probe real
    # usernames to confirm, and a credential for the coercion probe's SMB session.
    samba-tool user create alice   'Alice#Pass1!'   --given-name=Alice --surname=Anderson
    samba-tool user create bob     'Bob#Pass1234!'  --given-name=Bob   --surname=Brown
    samba-tool user create svc_sql 'Svc#Sql2026!'   --given-name=SQL   --surname=Service

    # Use the Samba-provisioned krb5.conf for any in-container krb5 tooling.
    cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf || true

    touch /var/lib/samba/.heaven-provisioned
fi

# Run the AD DC in the foreground so the container stays up and signals proxy.
exec samba --foreground --no-process-group --debuglevel=1
