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

    # ── Seed authenticated-tier misconfigurations so HEAVEN's advanced AD checks
    # have a real DC to confirm against. Each is a genuine, well-known AD
    # escalation primitive expressed against this throwaway lab's directory. They
    # are best-effort (the container must still boot for the credential-free
    # Kerberos/coercion benchmark even if a step is unsupported on this Samba
    # build), so a failure logs a warning rather than aborting.
    BASEDN="$(ldbsearch -H /var/lib/samba/private/sam.ldb -b '' -s base \
                defaultNamingContext 2>/dev/null \
                | sed -n 's/^defaultNamingContext: //p' | head -1)"
    BASEDN="${BASEDN:-DC=heaven,DC=local}"
    echo "heaven-lab: base DN = ${BASEDN}"

    # Kerberoasting target: give svc_sql (a NON-privileged account) an SPN. A real
    # DC then answers Kerberoasting enumeration with a service account that must be
    # reported HIGH, never critical (it is not adminCount=1), the live guard for
    # the severity false positive.
    samba-tool spn add "MSSQLSvc/dc1.heaven.local:1433" svc_sql \
        || echo "heaven-lab: WARN could not add SPN to svc_sql"

    # DCSync: grant Authenticated Users (SDDL alias AU = S-1-5-11, a NON-default
    # principal) the DS-Replication-Get-Changes[-All] extended rights on the
    # domain head. This is the ground truth a DCSync detector must confirm from
    # the domain object security descriptor.
    samba-tool dsacl set --objectdn="${BASEDN}" \
        --sddl="(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;AU)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;AU)" \
        || echo "heaven-lab: WARN could not grant replication rights"

    # ACL takeover edge: grant Authenticated Users GenericAll over the Tier-0
    # "Domain Admins" group, so any user can add themselves to it. The ACL-abuse
    # detector must confirm this from the group security descriptor and rate it
    # critical (Tier-0).
    samba-tool dsacl set --objectdn="CN=Domain Admins,CN=Users,${BASEDN}" \
        --sddl="(A;;GA;;;AU)" \
        || echo "heaven-lab: WARN could not grant GenericAll on Domain Admins"

    # Use the Samba-provisioned krb5.conf for any in-container krb5 tooling.
    cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf || true

    touch /var/lib/samba/.heaven-provisioned
fi

# Run the AD DC in the foreground so the container stays up and signals proxy.
exec samba --foreground --no-process-group --debuglevel=1
