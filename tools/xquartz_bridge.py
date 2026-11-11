#!/usr/bin/env python3
"""Relay a loopback TCP port to XQuartz's local display socket.

XQuartz listens only on a Unix socket by default (``nolisten_tcp``). Docker
containers on macOS reach the host's loopback as ``host.docker.internal``, so
this relay lets them draw on XQuartz as ``DISPLAY=host.docker.internal:0``
without enabling XQuartz's TCP listener or turning off access control: clients
still need XQuartz's cookie (see tools/docker_matrix.sh).

    python3 tools/xquartz_bridge.py --listen 127.0.0.1:6000 --socket "$DISPLAY"
"""

from __future__ import annotations

import argparse
import asyncio
import os


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()


async def _serve(host: str, port: int, socket_path: str) -> None:
    async def handle(client_reader, client_writer):
        try:
            server_reader, server_writer = await asyncio.open_unix_connection(socket_path)
        except OSError:
            client_writer.close()
            return
        await asyncio.gather(_pipe(client_reader, server_writer), _pipe(server_reader, client_writer))

    server = await asyncio.start_server(handle, host, port)
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--listen", default="127.0.0.1:6000", help="loopback address:port (display :0 is port 6000)")
    parser.add_argument("--socket", default=os.environ.get("DISPLAY", ""), help="XQuartz's socket (macOS sets DISPLAY to it)")
    args = parser.parse_args()
    host, _, port = args.listen.rpartition(":")
    if host not in ("127.0.0.1", "localhost", "::1"):
        parser.error("listen on a loopback address only")
    if not os.path.exists(args.socket):
        parser.error(f"no display socket at {args.socket!r} (is XQuartz running?)")
    try:
        asyncio.run(_serve(host, int(port), args.socket))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
