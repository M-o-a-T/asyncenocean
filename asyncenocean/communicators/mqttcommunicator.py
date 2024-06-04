# -*- encoding: utf-8 -*-

from contextlib import asynccontextmanager
from distmqtt.client import open_mqttclient
from distmqtt.codecs import MsgPackCodec

from .communicator import Communicator
from ..protocol.packet import Packet

import logging
logger = logging.getLogger(__name__)

class _MQTTCommunicator(Communicator):
    def __init__(self, channel, topic, **kw):
        super().__init__(None, **kw)
        self.channel = channel
        self.topic = topic

    async def receive(self):
        async for msg in self.channel:
            if not isinstance(msg.data, (list,tuple)) or len(msg.data) < 2:
                logger.warning("Inappropriate message: %r", msg.data)
                continue
            p = Packet.parse_msg(*msg.data)
            print(p.parse_eep(2,2))
            return p

    async def send(self, msg):
        if msg.optional:
            msg = [msg.packet_type, msg.data.bytes, msg.optional.bytes]
        else:
            msg = [msg.packet_type, msg.data.bytes]
        await self.channel.publish(topic=self.topic, message=msg)

@asynccontextmanager
async def MQTTCommunicator(uri='mqtt://localhost/', topic_in="/test/enocean/in", topic_out="test/enocean/out", **kw):
    async with open_mqttclient() as C:
        await C.connect(uri=uri)
        async with C.subscription(topic_in, codec=MsgPackCodec()) as CH:
            async with _MQTTCommunicator(CH, topic_out) as CM:
                yield CM

