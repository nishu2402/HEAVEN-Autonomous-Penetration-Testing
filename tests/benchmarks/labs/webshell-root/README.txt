HEAVEN webshell detection lab — INERT signature decoys.
=======================================================

Every file in this directory is a DECOY. Each one carries the *fingerprint* of a
well-known webshell (the string HEAVEN's read-only webshell sweep keys on) but
contains NO functional shell code — no eval of attacker input, no command
execution, no file manager, no upload handler. They are the EICAR equivalent for
webshells: enough signal to prove the detector fires, zero offensive capability.

nginx serves them as static text (there is no PHP interpreter in the container),
so even the one file that contains a China-Chopper-style `@eval($_POST[...])`
token is never executed — it is returned verbatim, which is exactly what a
scanner sees when a real dropped shell's source or rendered banner is exposed.

This lab proves, live, that `heaven/vulnscan/malware_scan.py::scan_malware_targets`
detects both webshell detection paths against a real HTTP server:
  * named-shell response signatures (c99 / r57 / b374k / WSO / IndoXploit / Alfa)
  * the YARA generic path (eval fed from a PHP superglobal), which had been
    unit-tested only.
