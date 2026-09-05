# Bundled fonts

These fonts are self-hosted so the HEAVEN console has **no external dependency**
at runtime: it renders correctly offline and in air-gapped engagements, and it
never phones home to a third-party font CDN (an opsec and privacy requirement for
an offensive-security tool). Previously the UI pulled these from Google Fonts,
which failed with connection errors on any network-restricted host and leaked a
request to Google on every load.

Both are variable fonts (one file per family, latin subset, covering every weight
the UI uses) served originally through the [Fontsource](https://fontsource.org)
project.

| Family          | File                              | Source                                              | License |
| --------------- | --------------------------------- | --------------------------------------------------- | ------- |
| Inter           | `inter-latin-var.woff2`           | https://github.com/rsms/inter                       | OFL-1.1 |
| JetBrains Mono  | `jetbrains-mono-latin-var.woff2`  | https://github.com/JetBrains/JetBrainsMono          | OFL-1.1 |

Both are licensed under the SIL Open Font License, Version 1.1. See `OFL.txt`.
The OFL permits bundling and redistribution with the accompanying software; the
license text and copyright notices are retained here as it requires.
