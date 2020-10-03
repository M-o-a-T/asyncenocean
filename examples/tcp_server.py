#!/usr/bin/env python
# -*- encoding: utf-8 -*-
from asyncenocean.consolelogger import init_logging
from asyncenocean import Communicator
from asyncenocean.protocol.constants import PACKET, RORG
import sys
import os

import anyio

port = int(os.environ.get("PORT",9637))

async def run(stream):
    try:
        async with Communicator(stream) as communicator:
            while True:
                packet = await communicator.receive()
                if packet.packet_type == PACKET.RADIO_ERP1 and packet.rorg == RORG.BS4:
                    for k in packet.parse_eep(0x02, 0x05):
                        print('%s: %s' % (k, packet.parsed[k]))
                if packet.packet_type == PACKET.RADIO_ERP1 and packet.rorg == RORG.BS1:
                    for k in packet.parse_eep(0x00, 0x01):
                        print('%s: %s' % (k, packet.parsed[k]))
                if packet.packet_type == PACKET.RADIO_ERP1 and packet.rorg == RORG.RPS:
                    for k in packet.parse_eep(0x02, 0x02):
                        print('%s: %s' % (k, packet.parsed[k]))
    except (EnvironmentError, anyio.EndOfStream):
        pass

async def listen(port):
    listener = await anyio.create_tcp_listener(local_port=port)
    await listener.serve(run)

anyio.run(listen, port, backend="trio")
