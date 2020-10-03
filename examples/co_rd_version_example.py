#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

"""
Example on getting the information about the EnOcean controller.
The sending is happening between the application and the EnOcean controller,
no wireless communication is taking place here.

The command used here is specified as 1.10.5 Code 03: CO_RD_VERSION
in the ESP3 document.
"""

from asyncenocean.consolelogger import init_logging
from asyncenocean import SerialCommunicator
from asyncenocean.protocol.packet import Packet
from asyncenocean.protocol.constants import PACKET
from asyncenocean import utils
import sys
import os
import anyio

init_logging()
"""
'/dev/ttyUSB0' might change depending on where your device is.
To prevent running the app as root, change the access permissions:
'sudo chmod 777 /dev/ttyUSB0'
"""
port = os.environ.get("PORT","/dev/ttyUSB0")
packet = Packet(PACKET.COMMON_COMMAND, [0x03])

async def run(port):
    async with SerialCommunicator(port) as communicator:
        print("Base ID", communicator.base_id)
        await communicator.send(packet)
        async with anyio.fail_after(1):
            receivedPacket = await communicator.receive()
        if receivedPacket.packet_type == PACKET.RESPONSE:
            print('Return Code:', utils.to_hex_string(receivedPacket.data[0]))
            print('APP version:', utils.to_hex_string(receivedPacket.data[1:5]))
            print('API version:', utils.to_hex_string(receivedPacket.data[5:9]))
            print('Chip ID:', utils.to_hex_string(receivedPacket.data[9:13]))
            print('Chip Version:', utils.to_hex_string(receivedPacket.data[13:17]))
            print('App Description Version:', utils.to_hex_string(receivedPacket.data[17:]))
            print('App Description Version (ASCII):', receivedPacket.data[17:])

anyio.run(run, port, backend="trio")
