# -*- encoding: utf-8 -*-
from __future__ import print_function, unicode_literals, division, absolute_import
import logging
import datetime

from ..protocol.packet import Packet, UTETeachInPacket
from ..protocol.constants import PACKET, PARSE_RESULT, RETURN_CODE

import anyio

class Communicator(anyio.abc.ObjectStream):
    '''
    Communicator base-class for EnOcean.
    Not to be used directly, only serves as base class for SerialCommunicator etc.
    '''
    logger = logging.getLogger('enocean.communicators.Communicator')

    def __init__(self, stream: anyio.abc.ByteStream, teach_in=True, client=False):
        self._stream = stream
        # Input buffer
        self._buffer = bytearray()
        # Internal variable for the Base ID of the module.
        self._base_id = None
        # Should new messages be learned automatically? Defaults to True.
        # TODO: Not sure if we should use CO_WR_LEARNMODE??
        self.teach_in = teach_in
        self.client = client

    async def _init_base(self):
        # Send COMMON_COMMAND 0x08, CO_RD_IDBASE request to the module
        await self.send(Packet(PACKET.COMMON_COMMAND, data=[0x08]))
        # Wait a second until the radio replies.
        async with anyio.move_on_after(10000):
            while True:
                packet = await self.receive()
                if packet.packet_type == PACKET.RESPONSE and packet.response == RETURN_CODE.OK and len(packet.response_data) == 4:
                    # Base ID is set in the response data.
                    self._base_id = packet.response_data
                    return

    async def __aenter__(self):
        if not self.client:
            await self._init_base()
        return self

    async def __aexit__(self, *tb):
        pass

    async def aclose(self):
        pass


    async def send(self, packet):
        await self._stream.send(bytearray(packet.build()))

    async def send_eof(self):
        raise NotImplementedError

    async def _read(self):
        return await self.__ser.receive()

    async def receive(self):
        ''' Parses messages and puts them to receive queue '''
        # Loop while we get new messages
        while True:
            res = Packet.parse_msg(self._buffer)
            # If message is incomplete -> break the loop
            if isinstance(res, int):
                self._buffer.extend(bytearray(await self._stream.receive(16)))
                continue

            # If message is OK, add it to receive queue or send to the callback method
            if res is not None:
                packet = res
                packet.received = datetime.datetime.now()
                self.logger.debug(packet)

                if self.teach_in and isinstance(packet, UTETeachInPacket):
                    response_packet = packet.create_response_packet(self.base_id)
                    self.logger.info('Sending response to UTE teach-in.')
                    await self.send(response_packet)

                return packet

    @property
    def base_id(self):
        ''' Fetches Base ID from the transmitter, if required. Otherwise returns the currently set Base ID. '''
        # If base id is already set, return it.
        if self._base_id is not None:
            return self._base_id


    @base_id.setter
    def base_id(self, base_id):
        ''' Sets the Base ID manually, only for testing purposes. '''
        self._base_id = base_id
