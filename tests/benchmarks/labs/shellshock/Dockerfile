# HEAVEN benchmark: Shellshock (CVE-2014-6271) lab.
#
# A GENUINELY vulnerable target: unpatched bash 4.3 (built from the GNU source
# tarball, before the bash43-025 fix) invoked as a CGI script by busybox httpd.
# A request header of the form `() { :; }; <cmd>` is imported by the vulnerable
# bash as an environment function definition and its trailing command is
# executed — real remote command execution, reproduced from source, not mocked.
#
# SECURITY: bound to loopback by the compose file; the only command it will run
# is the one HEAVEN injects with a per-run token, whose output goes to HEAVEN's
# own callback listener. Nothing here is exposed off the host.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        wget gcc make libc6-dev bison ca-certificates busybox-static \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# bash 4.3 vanilla == pre-Shellshock-patch == vulnerable to CVE-2014-6271.
RUN wget -q https://ftp.gnu.org/gnu/bash/bash-4.3.tar.gz \
    && tar xzf bash-4.3.tar.gz

# Older gcc defaults reject bash 4.3's K&R-era prototypes; relax them so the
# vanilla (unpatched) source builds cleanly on a modern toolchain.
RUN cd bash-4.3 \
    && CFLAGS="-std=gnu89 -Wno-implicit-int -Wno-implicit-function-declaration -Wno-return-mismatch" \
       ./configure --without-bash-malloc >/dev/null 2>&1 \
    && make -j"$(nproc)" >/dev/null 2>&1 \
    && cp bash /bin/bash43 \
    && /bin/bash43 --version | head -1

RUN mkdir -p /www/cgi-bin
COPY test.cgi /www/cgi-bin/test
RUN chmod +x /www/cgi-bin/test

# A real Linux target (Metasploitable, most distros) ships netcat; busybox-static
# provides the applet but not the `nc` name on PATH, so create it. This is the
# post-exploitation channel HEAVEN's reverse-callback proof uses.
RUN ln -sf /bin/busybox /bin/nc

EXPOSE 80
# busybox httpd passes request headers to CGI scripts as HTTP_* env vars, which
# is exactly what makes the bash CGI reachable by a Shellshock header.
CMD ["busybox", "httpd", "-f", "-p", "80", "-h", "/www"]
