# -*- encoding: utf-8 -*-
from __future__ import print_function, unicode_literals, division, absolute_import
import logging
import anyio

from .communicator import Communicator

from contextlib import asynccontextmanager

@asynccontextmanager
async def TCPCommunicator(host='localhost', port=9637, **kw):
    async with await anyio.connect_tcp(host, port) as client:
        async with Communicator(client, **kw) as comm:
            yield comm

