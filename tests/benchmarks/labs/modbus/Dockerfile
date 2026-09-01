# Real Modbus/TCP PLC emulator for the HEAVEN IoT/OT lab.
# Uses pymodbus (a real, independent Modbus stack) so HEAVEN's protocol probe
# talks to a genuine Modbus server, not a hand-rolled responder tuned to pass.
FROM python:3.12-slim

RUN pip install --no-cache-dir "pymodbus==3.6.9"

COPY server.py /server.py

EXPOSE 502
CMD ["python", "/server.py"]
