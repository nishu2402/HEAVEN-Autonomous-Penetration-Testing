"""The authenticated crawler must never follow a logout / session-destroying URL.

Following one logs the crawler (and every scanner sharing the session) out, after
which protected pages redirect to login and detection silently collapses — the
exact failure that reduced the DVWA benchmark's authenticated recall to ~0. These
tests pin the ``_is_session_destroying`` classifier so that regression can't
return. See heaven/recon/web_crawler.py.
"""

from __future__ import annotations

import pytest

from heaven.recon.web_crawler import _is_session_destroying as ends_session


@pytest.mark.parametrize(
    "url",
    [
        "http://t/logout.php",
        "http://t/logout",
        "http://t/user/logout/",
        "http://t/account/log-out",
        "http://t/auth/signout",
        "http://t/auth/sign-out",
        "http://t/account/logoff",
        "http://t/api/session/destroy",
        "http://t/session/end",
        "http://t/deauthenticate",
        "http://t/index.php?action=logout",
        "http://t/index.php?do=logoff",
        "http://t/app?redirect=x&op=signout",
    ],
)
def test_session_destroying_urls_are_flagged(url: str) -> None:
    assert ends_session(url) is True, f"{url!r} should be treated as session-ending"


@pytest.mark.parametrize(
    "url",
    [
        "",
        "http://t/vulnerabilities/sqli/?id=1&Submit=Submit",
        "http://t/vulnerabilities/exec/",
        "http://t/login.php",          # logging IN is not logging out
        "http://t/about.php",
        "http://t/blog/hangout",       # 'out' substring, not a logout token
        "http://t/store/checkout",     # 'out' substring, not a logout token
        "http://t/products?page=2",
        "http://t/catalog/logistics",  # 'log' prefix but not 'logout'
    ],
)
def test_normal_urls_are_not_flagged(url: str) -> None:
    assert ends_session(url) is False, f"{url!r} should NOT be treated as session-ending"
