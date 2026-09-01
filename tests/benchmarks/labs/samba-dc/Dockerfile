# A real Samba Active Directory Domain Controller, provisioned from scratch.
#
# This is a genuine AD DC (Samba's AD-DC server role speaks real Kerberos on
# 88, LDAP on 389, SMB/RPC on 445/135), not a mock. HEAVEN's credential-free
# Kerberos pre-auth probe and its NTLM-coercion surface probe run against it to
# prove the AD-mode detections work end to end against a service that actually
# speaks the protocols.
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

# samba (AD DC), the ldb tools used to inspect the directory, krb5 client libs
# and winbind. krb5-config is pre-seeded so the krb5 package install does not
# block on an interactive realm prompt.
RUN echo "krb5-config krb5-config/default_realm string HEAVEN.LOCAL" \
        | debconf-set-selections \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        samba samba-ad-provision smbclient winbind libnss-winbind libpam-winbind \
        krb5-user samba-dsdb-modules samba-vfs-modules ldb-tools \
        procps iproute2 dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Kerberos (88), RPC endpoint mapper (135), NetBIOS (139), LDAP (389),
# SMB (445), kpasswd (464), LDAPS (636).
EXPOSE 88 135 139 389 445 464 636

ENTRYPOINT ["/entrypoint.sh"]
