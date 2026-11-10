# HEAVEN business-logic mass-assignment lab.
#
# A deliberately mass-assignable sign-up app baked onto the stock Python image.
# Pure standard library, so there is nothing to install: the only build step is
# copying the app in, which also sidesteps a host bind-mount (colima's VM cannot
# always mount an arbitrary host path). Inert by construction: it persists
# nothing and runs no user input as code. The compose publishes it on loopback
# only; it is deliberately insecure, so never expose it on a reachable 0.0.0.0.
FROM python:3.12-slim

WORKDIR /app
COPY massassign_app.py /app/massassign_app.py

EXPOSE 80
# 0.0.0.0 inside the isolated container; the compose maps it to 127.0.0.1 only.
CMD ["python", "/app/massassign_app.py", "0.0.0.0", "80"]
