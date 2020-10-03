# -*- encoding: utf-8 -*-
from __future__ import print_function, unicode_literals, division, absolute_import
import logging
import time

from enocean.communicators.communicator import Communicator

from anyio_serial import Serial
from contextlib import asynccontextmanager

@asynccontextmanager
async def SerialCommunicator(port='/dev/ttyAMA0'):
    async with Serial(port, 57600).open() as serial:
        async with Communicator(serial) as comm:
            yield comm

