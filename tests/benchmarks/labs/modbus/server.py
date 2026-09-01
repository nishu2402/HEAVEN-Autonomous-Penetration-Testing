"""A real, unauthenticated Modbus/TCP server for the HEAVEN IoT/OT lab.

This is not a mock that returns whatever HEAVEN's probe wants to see — it is a
genuine `pymodbus` server speaking the real Modbus/TCP protocol with no
authentication (which is Modbus's real-world weakness: the protocol has no auth
at all). HEAVEN's `probe_modbus` performs a real Read-Device-Identification
request (FC 43 / MEI 14) and this server answers it exactly as a real PLC/RTU
would, because a `ModbusDeviceIdentification` is configured.

Read-only from HEAVEN's side; the server exposes coils/registers an operator
could read or write, which is the point of the finding.
"""

from __future__ import annotations

import logging

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.server import StartTcpServer

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("modbus-lab")


def _context() -> ModbusServerContext:
    """A single slave context that answers on any unit id, pre-seeded with some
    coils/registers so reads return data."""
    block = ModbusSequentialDataBlock(0x00, [0] * 256)
    store = ModbusSlaveContext(di=block, co=block, hr=block, ir=block, zero_mode=True)
    return ModbusServerContext(slaves=store, single=True)


def _identity() -> ModbusDeviceIdentification:
    """Populate the device identification so a Read-Device-Identification (FC 43)
    request gets a valid response — exactly what a fingerprintable PLC exposes."""
    ident = ModbusDeviceIdentification()
    ident.VendorName = "HEAVEN-Lab"
    ident.ProductCode = "PLC"
    ident.VendorUrl = "https://example.invalid"
    ident.ProductName = "HEAVEN Modbus Lab PLC"
    ident.ModelName = "Lab-PLC-1"
    ident.MajorMinorRevision = "1.0"
    return ident


def main() -> None:
    log.info("Starting unauthenticated Modbus/TCP lab server on 0.0.0.0:502")
    StartTcpServer(
        context=_context(),
        identity=_identity(),
        address=("0.0.0.0", 502),
    )


if __name__ == "__main__":
    main()
