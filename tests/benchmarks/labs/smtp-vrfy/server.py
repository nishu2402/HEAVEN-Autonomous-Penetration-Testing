"""A real SMTP server (aiosmtpd) that leaks valid users via VRFY.

Like the Modbus lab uses pymodbus, this uses aiosmtpd — a real, independent SMTP
stack — so HEAVEN talks to a genuine SMTP server, not a hand-rolled responder
tuned to pass. VRFY is left ENABLED and answers against a REAL local-user set:
250 for a user that exists, 550 for one that does not. That is the classic
sendmail-style user-enumeration misconfiguration (RFC 821 VRFY exposing the
account list). The differential is driven purely by real user existence — the
server never inspects whether the probe is HEAVEN's.
"""
import asyncio

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP as SMTPServer

# The MTA's real local accounts. VRFY reveals membership in THIS set.
KNOWN_USERS = {"postmaster", "root", "admin", "webmaster", "alice", "bob"}


class VRFYEnabledSMTP(SMTPServer):
    async def smtp_VRFY(self, arg):
        if not arg:
            await self.push("501 Syntax: VRFY <address>")
            return
        user = arg.strip().lstrip("<").rstrip(">").split("@")[0].lower()
        if user in KNOWN_USERS:
            await self.push(f"250 2.1.5 <{user}@heaven.lab>")
        else:
            await self.push("550 5.1.1 <%s>... User unknown" % user)


class _Handler:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        return "250 Message accepted for delivery"


class _Controller(Controller):
    def factory(self):
        return VRFYEnabledSMTP(self.handler, hostname="heaven.lab")


if __name__ == "__main__":
    c = _Controller(_Handler(), hostname="0.0.0.0", port=25)
    c.start()
    loop = asyncio.new_event_loop()
    loop.run_forever()
