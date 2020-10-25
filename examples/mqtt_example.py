#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
from asyncenocean.consolelogger import init_logging
from asyncenocean import utils
from asyncenocean.communicators.mqttcommunicator import MQTTCommunicator
from asyncenocean.protocol.packet import RadioPacket
from asyncenocean.protocol.constants import PACKET, RORG
import sys
import os
import anyio

init_logging()

port = os.environ.get("URI","mqtt://localhost/")
topic = os.environ.get("TOPIC","test/enocean")
topic_in = os.environ.get("TOPIC_IN",topic+"/in")
topic_out = os.environ.get("TOPIC_OUT",topic+"/out")

async def run(port):
    async with MQTTCommunicator(port, topic_in=topic_in, topic_out=topic_out) as communicator:
        # Loop to empty the queue...
        print('The Base ID of your module is %s.' % utils.to_hex_string(communicator.base_id))

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
