#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
from asyncenocean.consolelogger import init_logging
from asyncenocean import utils
from asyncenocean import SerialCommunicator
from asyncenocean.protocol.packet import RadioPacket
from asyncenocean.protocol.constants import PACKET, RORG
import sys
import os
import anyio

def assemble_radio_packet(transmitter_id):
    return RadioPacket.create(rorg=RORG.BS4, rorg_func=0x20, rorg_type=0x01,
                              sender=transmitter_id,
                              CV=50,
                              TMP=21.5,
                              ES='true')


init_logging()


# endless loop receiving radio packets
port = os.environ.get("PORT","/dev/ttyUSB0")  

async def run(port):
    async with SerialCommunicator(port) as communicator:
        # Loop to empty the queue...
        print('The Base ID of your module is %s.' % utils.to_hex_string(communicator.base_id))
        if communicator.base_id is not None:
            print('Sending example package.')
            await communicator.send(assemble_radio_packet(communicator.base_id))

        while True:
            try:
                async with anyio.fail_after(10):
                    packet = await communicator.receive()
            except TimeoutError:
                break
            if packet.packet_type == PACKET.RADIO_ERP1 and packet.rorg == RORG.VLD:
                packet.select_eep(0x05, 0x00)
                packet.parse_eep()
                for k in packet.parsed:
                    print('%s: %s' % (k, packet.parsed[k]))
            if packet.packet_type == PACKET.RADIO_ERP1 and packet.rorg == RORG.BS4:
                # parse packet with given FUNC and TYPE
                for k in packet.parse_eep(0x02, 0x05):
                    print('%s: %s' % (k, packet.parsed[k]))
            if packet.packet_type == PACKET.RADIO_ERP1 and packet.rorg == RORG.BS1:
                # alternatively you can select FUNC and TYPE explicitely
                packet.select_eep(0x00, 0x01)
                # parse it
                packet.parse_eep()
                for k in packet.parsed:
                    print('%s: %s' % (k, packet.parsed[k]))
            if packet.packet_type == PACKET.RADIO_ERP1 and packet.rorg == RORG.RPS:
                for k in packet.parse_eep(0x02, 0x02):
                    print('%s: %s' % (k, packet.parsed[k]))

anyio.run(run, port, backend="trio")
