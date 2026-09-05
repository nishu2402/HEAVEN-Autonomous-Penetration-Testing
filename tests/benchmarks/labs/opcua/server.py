"""Minimal but REAL OPC-UA server (asyncua) for HEAVEN's OT lab.

asyncua is the de-facto Python OPC-UA stack; this is a genuine OPC-UA server
answering the OPC-UA Connection Protocol (HEL -> ACK) handshake and exposing a
node, with no security policy (anonymous) — a realistic exposed-OT posture.
Read-only from the scanner's side: HEAVEN only performs the HEL/ACK transport
handshake (probe_opcua).
"""
import asyncio

from asyncua import Server


async def main() -> None:
    server = Server()
    await server.init()
    server.set_endpoint("opc.tcp://0.0.0.0:4840/heaven/server/")
    server.set_server_name("HEAVEN OT Lab OPC-UA Server")
    idx = await server.register_namespace("http://heaven.lab/ot")
    dev = await server.nodes.objects.add_object(idx, "PLC")
    await dev.add_variable(idx, "Temperature", 21.5)
    async with server:
        while True:
            await asyncio.sleep(1.0)


if __name__ == "__main__":
    asyncio.run(main())
