#!/usr/bin/env python
# -*- encoding: utf-8 -*-
from asyncenocean.consolelogger import init_logging
from asyncenocean import SerialCommunicator
from asyncenocean import TCPCommunicator
import os
import anyio

port = os.environ.get("PORT","/dev/ttyUSB0")
tcpport = int(os.environ.get("TCPPORT",9637))

init_logging()
async def run():
    async with SerialCommunicator(port) as ser:
        try:
            async with TCPCommunicator(port=tcpport, client=True) as tcp:
                async def transfer(a,b):
                    while True:
                        packet = await a.receive()
                        await b.send(packet)
                async with anyio.create_task_group() as tg:
                    await tg.spawn(transfer,ser,tcp)
                    await tg.spawn(transfer,tcp,ser)
        except anyio.EndOfStream:
            pass

anyio.run(run, backend="trio")
