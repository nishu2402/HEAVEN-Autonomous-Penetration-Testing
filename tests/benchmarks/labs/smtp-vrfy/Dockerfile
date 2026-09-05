# Real SMTP server (aiosmtpd) that leaks valid users via VRFY, for HEAVEN's
# EMAIL-mode user-enumeration proof. aiosmtpd is a real, independent SMTP stack.
FROM python:3.12-slim
RUN pip install --no-cache-dir "aiosmtpd==1.4.6"
COPY server.py /server.py
EXPOSE 25
CMD ["python", "/server.py"]
