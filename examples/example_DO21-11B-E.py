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
from asyncenocean import SerialCommunicator
from asyncenocean.protocol.packet import RadioPacket, UTETeachInPacket
from asyncenocean.protocol.constants import RORG

import anyio

async def send_command(comm, destination, output_value):
    comm.send(
        RadioPacket.create(rorg=RORG.VLD, rorg_func=0x01, rorg_type=0x01, destination=destination, sender=comm.base_id, command=1, IO=0x1E, OV=output_value)
    )


async def turn_on(c, destination):
    await send_command(c, destination, 100)


async def turn_off(c, destination):
    await send_command(c, destination, 0)


# endless loop receiving radio packets
async def run(port):
    async with SerialCommunicator(port) as communicator:
        print("Base ID", communicator.base_id)

        # Example of turning switches on and off
        await turn_on(communicator, [0x01, 0x94, 0xB9, 0x46])
        # Needs a bit of sleep in between, working too fast :S
        await anyio.sleep(0.1)
        await turn_on(communicator, [0x01, 0x94, 0xE3, 0xB9])
        await anyio.sleep(1)

        await turn_off(communicator, [0x01, 0x94, 0xB9, 0x46])
        await anyio.sleep(0.1)

anyio.run(run, port, backend="trio")

