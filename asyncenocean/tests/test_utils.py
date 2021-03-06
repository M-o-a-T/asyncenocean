# -*- encoding: utf-8 -*-
from __future__ import print_function, unicode_literals, division, absolute_import
from asyncenocean import utils


def test_get_bit():
    assert utils.get_bit(1, 0) == 1
    assert utils.get_bit(8, 3) == 1
    assert utils.get_bit(6, 2) == 1
    assert utils.get_bit(6, 1) == 1


def test_to_hex_string():
    assert utils.to_hex_string(0) == '00'
    assert utils.to_hex_string(15) == '0F'
    assert utils.to_hex_string(16) == '10'
    assert utils.to_hex_string(22) == '16'

    assert utils.to_hex_string([0, 15, 16, 22]) == '00:0F:10:16'
    assert utils.to_hex_string([0x00, 0x0F, 0x10, 0x16]) == '00:0F:10:16'
