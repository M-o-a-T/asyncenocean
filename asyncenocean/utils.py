# -*- encoding: utf-8 -*-
from __future__ import print_function, unicode_literals, division, absolute_import


def get_bit(byte, bit):
    ''' Get bit value from byte '''
    return (byte >> bit) & 0x01


def combine_hex(data):
    ''' Combine list of integer values to one big integer '''
    output = 0x00
    for i, value in enumerate(reversed(data)):
        output |= (value << i * 8)
    return output


def to_hex_string(data):
    ''' Convert list of integers to a hex string, separated by ":" '''
    if isinstance(data, int):
        return '%02X' % data
    return ':'.join([('%02X' % o) for o in data])

