#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
Example to show automatic UTE Teach-in responses using
http://www.g-media.fr/prise-gigogne-enocean.html

Waits for UTE Teach-ins, sends the response automatically and prints the ID of new device.
'''

import sys
import os
import time
import traceback
from asyncenocean import utils
from asyncenocean import SerialCommunicator
from asyncenocean.protocol.packet import RadioPacket, UTETeachInPacket
from asyncenocean.protocol.constants import RORG

import anyio

print('Press and hold the teach-in button on the plug now, till it starts turning itself off and on (about 10 seconds or so...)')
devices_learned = []

port = os.environ.get("PORT","/dev/ttyUSB0")

async def set_position(comm, destination, percentage):
    await comm.send(
        RadioPacket.create(rorg=RORG.VLD, rorg_func=0x05, rorg_type=0x00, destination=destination, sender=comm.base_id, command=1, POS=percentage)
    )

# endless loop receiving radio packets
async def run(port):
    async with SerialCommunicator(port) as communicator:
        await set_position(communicator, [0x05, 0x0F, 0x0B, 0xEA], 50)
        while True:
            try:
                async with anyio.fail_after(10):
                    packet = await communicator.receive()
            except TimeoutError:
                break
            if isinstance(packet, UTETeachInPacket):
                print('New device learned! The ID is %s.' % (packet.sender_hex))
                devices_learned.append(packet.sender)

print('Devices learned during this session: %s' % (', '.join([utils.to_hex_string(x) for x in devices_learned])))

anyio.run(run, port, backend="trio")

