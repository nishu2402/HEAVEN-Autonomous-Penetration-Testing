# A real Postfix MTA, deliberately misconfigured as an OPEN RELAY.
#
# This is a genuine Postfix 3.x server (not a mock SMTP responder). The
# entrypoint rewrites main.cf so the box trusts the whole world and permits any
# recipient, which is exactly what an open relay is. HEAVEN's non-intrusive relay
# probe then proves smtp_open_relay against a service that actually speaks SMTP.
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

# Pre-seed debconf so the postfix package installs non-interactively (it would
# otherwise open an ncurses dialog for mailer type + mail name).
RUN echo "postfix postfix/main_mailer_type string 'Internet Site'" \
        | debconf-set-selections \
    && echo "postfix postfix/mailname string relay.heaven.local" \
        | debconf-set-selections \
    && apt-get update \
    && apt-get install -y --no-install-recommends postfix \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 25

ENTRYPOINT ["/entrypoint.sh"]
