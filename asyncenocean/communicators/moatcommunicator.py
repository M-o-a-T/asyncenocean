# -*- encoding: utf-8 -*-
from __future__ import print_function, unicode_literals, division, absolute_import
import logging
import time

from .communicator import Communicator

from moat.micro.proto.stream import BufAnyio
from moat.micro.part.serial import Serial
from contextlib import asynccontextmanager

@asynccontextmanager
async def MoatCommunicator(cfg):
    """
    A Communicator that uses a MoaT bytestream.

    Params:
        port: serial config (keys: port, mode.rate, …)
        comm: Communicator config (keys: teach_in, …)
    """
    async with (
            BufAnyio(Serial(cfg["port"])) as serial,
            Communicator(serial, **cfg.get("comm",{})) as comm,
        ):
        yield comm

