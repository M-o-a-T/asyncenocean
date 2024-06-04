# -*- encoding: utf-8 -*-
from __future__ import print_function, unicode_literals, division, absolute_import
import logging
from bitstring import BitArray, Bits

from .. import utils
from . import crc8
from .eep import EEP
from .constants import PACKET, RORG, PARSE_RESULT, DB0, DB2, DB3, DB4, DB6


class Packet(object):
    '''
    Base class for Packet.
    Mainly used for for packet generation and
    Packet.parse_msg() / Packet.parse_buffer(buf) for parsing message.
    parse_*() returns subclass, if one is defined for the data type.
    '''
    eep = EEP()
    logger = logging.getLogger('enocean.protocol.packet')

    def __init__(self, packet_type, data=None, optional=None):
        self.packet_type = packet_type
        self.rorg = RORG.UNDEFINED
        self.rorg_func = None
        self.rorg_type = None
        self.rorg_manufacturer = None

        self.received = None

        self.data = BitArray(bytes(data) if data else '')
        self.optional = BitArray(bytes(optional) if optional else '')

        self.status = 0
        self.parsed = {}
        self.repeater_count = 0
        self._profile = None

        self.parse()

    def __str__(self):
        return '0x%02X %s %s %s' % (
            self.packet_type,
            [hex(o) for o in self.data],
            [hex(o) for o in self.optional],
            self.parsed)


    def __eq__(self, other):
        return self.packet_type == other.packet_type and self.rorg == other.rorg \
            and self.data == other.data and self.optional == other.optional

    @property
    def _bit_data(self):
        # First and last 5 bytes are always defined, so the data we're modifying is between them...
        # TODO: This is valid for the packets we're currently manipulating.
        # Needs the redefinition of Packet.data -> Packet.message.
        # Packet.data would then only have the actual, documented data-bytes.
        # Packet.message would contain the whole message.
        # See discussion in issue #14
        return self.data[8 : self.data.length-5*8]

    @_bit_data.setter
    def _bit_data(self, value):
        # The same as getting the data, first and last 5 bytes are omitted
        self.data = self.data[0:8] + value + self.data[-5*8:]

    @property
    def _bit_status(self):
        return BitArray(uint=self.status, length=8)

    @_bit_status.setter
    def _bit_status(self, value):
        self.status = value.uint

    @staticmethod
    def parse_buffer(buf):
        '''
        Parses message from buffer.
        returns:
            - if valid message: the message
            - if incomplete: #bytes required
            - if CRC error: None

        also modifies the buffer
        '''
        # If the buffer doesn't contain 0x55 (start char)
        # the buffer contains junk -> ignore
        while True:
            idx = buf.find(b'\x55')
            if idx == -1:
                buf.clear()
                return 7
            if idx > 0:
                del buf[0:idx]

            # Check CRC for header
            try:
                if buf[5] == crc8.calc(buf[1:5]):
                    break
            except IndexError:
                # message is incomplete, need this many more bytes
                return 7-len(buf)

            # Fail if doesn't match message: scan for next start
            Packet.logger.error('Header CRC error!')
            # Return CRC_MISMATCH
            del buf[0:1]
            # return None

        data_len = (buf[1] << 8) | buf[2]
        opt_len = buf[3]

        # Header: 6 bytes, data, optional data and data checksum
        msg_len = 6 + data_len + opt_len + 1
        if len(buf) < msg_len:
            # If buffer isn't long enough, the message is incomplete
            return msg_len-len(buf)

        if buf[6 + data_len + opt_len] != crc8.calc(buf[6:6 + data_len + opt_len]):
            # Fail if doesn't match message
            Packet.logger.error('Data CRC error!')
            # Return CRC_MISMATCH
            del buf[0:1]
            return None

        # otherwise move the message off the buffer
        packet_type = buf[4]
        data = buf[6:6 + data_len]
        opt_data = buf[6 + data_len:6 + data_len + opt_len]

        del buf[0:msg_len]

        # If we got this far, everything went ok (?)
        return Packet.parse_msg(packet_type, data, opt_data)

    @staticmethod
    def parse_msg(packet_type, data, opt_data):
        """
        Parse a message (pre-split and CRC-checked)
        """

        if packet_type == PACKET.RADIO_ERP1:
            # Need to handle UTE Teach-in here, as it's a separate packet type...
            if data[0] == RORG.UTE:
                packet = UTETeachInPacket(packet_type, data, opt_data)
            else:
                packet = RadioPacket(packet_type, data, opt_data)
        elif packet_type == PACKET.RESPONSE:
            packet = ResponsePacket(packet_type, data, opt_data)
        elif packet_type == PACKET.EVENT:
            packet = EventPacket(packet_type, data, opt_data)
        else:
            packet = Packet(packet_type, data, opt_data)

        return packet

    @staticmethod
    def create(packet_type, rorg, rorg_func, rorg_type, direction=None, command=None,
               destination=None,
               sender=None,
               learn=False, **kwargs):
        '''
        Creates a packet ready for sending.
        Uses rorg, rorg_func and rorg_type to determine the values set based on EEP.
        Additional arguments (**kwargs) are used for setting the values.

        Currently only supports:
            - PACKET.RADIO_ERP1
            - RORGs RPS, BS1, BS4, VLD.

        TODO:
            - Require sender to be set? Would force the "correct" sender to be set.
            - Do we need to set telegram control bits?
              Might be useful for acting as a repeater?
        '''

        if packet_type != PACKET.RADIO_ERP1:
            # At least for now, only support PACKET.RADIO_ERP1.
            raise ValueError('Packet type not supported by this function.')

        if rorg not in [RORG.RPS, RORG.BS1, RORG.BS4, RORG.VLD]:
            # At least for now, only support these RORGS.
            raise ValueError('RORG not supported by this function.')

        if destination is None:
            Packet.logger.warning('Replacing destination with broadcast address.')
            destination = [0xFF, 0xFF, 0xFF, 0xFF]

        # TODO: Should use the correct Base ID as default.
        #       Might want to change the sender to be an offset from the actual address?
        if sender is None:
            Packet.logger.warning('Replacing sender with default address.')
            sender = [0xDE, 0xAD, 0xBE, 0xEF]

        if len(destination) != 4:
            raise ValueError('Destination must be 4 bytes.')

        if len(sender) != 4:
            raise ValueError('Sender must be 4 bytes.')

        packet = Packet(packet_type, data=[], optional=[])
        packet.rorg = rorg
        data = [packet.rorg]
        # Select EEP at this point, so we know how many bits we're dealing with (for VLD).
        packet.select_eep(rorg_func, rorg_type, direction, command)

        # Initialize data depending on the profile.
        if rorg in [RORG.RPS, RORG.BS1]:
            data.extend([0])
        elif rorg == RORG.BS4:
            data.extend([0, 0, 0, 0])
        else:
            data.extend([0] * int(packet._profile.get('bits', '1')))
        data.extend(sender)
        data.extend([0])
        # Always use sub-telegram 3, maximum dbm (as per spec, when sending),
        # and no security (security not supported as per EnOcean Serial Protocol).
        packet.optional = BitArray(bytes([3] + destination + [0xFF] + [0]))

        if command:
            # Set CMD to command, if applicable.. Helps with VLD.
            kwargs['CMD'] = command

        packet.data = BitArray(bytes=bytes(data))
        packet.set_eep(kwargs)
        if rorg in [RORG.BS1, RORG.BS4] and not learn:
            if rorg == RORG.BS1:
                packet.data[12] = 1
            if rorg == RORG.BS4:
                packet.data[36] = 1
        packet.data.overwrite(Bits(uint=packet.status,length=8), pos=packet.data.len-8)

        # Parse the built packet, so its class etc. corresponds to the received packages
        # For example, stuff like RadioPacket.learn should be set.
        packet = Packet.parse_msg(packet.packet_type, packet.data.bytes, packet.optional.bytes)
        packet.rorg = rorg
        packet.parse_eep(rorg_func, rorg_type, direction, command)
        return packet

    def parse(self):
        ''' Parse data from Packet '''
        # Parse status from messages
        if self.rorg in [RORG.RPS, RORG.BS1, RORG.BS4]:
            self.status = self.data.bytes[-1]
        if self.rorg == RORG.VLD:
            self.status = self.optional.bytes[-1]

        if self.rorg in [RORG.RPS, RORG.BS1, RORG.BS4]:
            # These message types should have repeater count in the last for bits of status.
            self.repeater_count = self._bit_status[4:].uint
        return self.parsed

    def select_eep(self, rorg_func, rorg_type, direction=None, command=None):
        ''' Set EEP based on FUNC and TYPE '''
        # set EEP profile
        self.rorg_func = rorg_func
        self.rorg_type = rorg_type
        self._profile = self.eep.find_profile(self._bit_data, self.rorg, rorg_func, rorg_type, direction, command)
        return self._profile is not None

    def parse_eep(self, rorg_func=None, rorg_type=None, direction=None, command=None):
        ''' Parse EEP based on FUNC and TYPE '''
        # set EEP profile, if demanded
        if rorg_func is not None and rorg_type is not None:
            self.select_eep(rorg_func, rorg_type, direction, command)
        # parse data
        provides, values = self.eep.get_values(self._profile, self._bit_data, self._bit_status)
        self.parsed.update(values)
        return list(provides)

    def set_eep(self, data):
        ''' Update packet data based on EEP. Input data is a dictionary with keys corresponding to the EEP. '''
        self._bit_data, self._bit_status = self.eep.set_values(self._profile, self._bit_data, self._bit_status, data)

    def build(self):
        ''' Build Packet for sending to EnOcean controller '''
        data_length = len(self.data.bytes)
        ords = bytearray([0x55, (data_length >> 8) & 0xFF, data_length & 0xFF, len(self.optional.bytes), int(self.packet_type)])
        ords.append(crc8.calc(ords[1:5]))
        ords.extend(self.data.bytes)
        ords.extend(self.optional.bytes)
        ords.append(crc8.calc(ords[6:]))
        return ords


class RadioPacket(Packet):
    destination = [0xFF, 0xFF, 0xFF, 0xFF]
    dBm = 0
    sender = [0xFF, 0xFF, 0xFF, 0xFF]
    learn = True
    contains_eep = False

    def __str__(self):
        packet_str = super(RadioPacket, self).__str__()
        return '%s->%s (%d dBm): %s' % (self.sender_hex, self.destination_hex, self.dBm, packet_str)

    @staticmethod
    def create(rorg, rorg_func, rorg_type, direction=None, command=None,
               destination=None, sender=None, learn=False, **kwargs):
        return Packet.create(PACKET.RADIO_ERP1, rorg, rorg_func, rorg_type,
                             direction, command, destination, sender, learn, **kwargs)

    @property
    def sender_int(self):
        return utils.combine_hex(self.sender)

    @property
    def sender_hex(self):
        return utils.to_hex_string(self.sender)

    @property
    def destination_int(self):
        return utils.combine_hex(self.destination)

    @property
    def destination_hex(self):
        return utils.to_hex_string(self.destination)

    def parse(self):
        self.destination = self.optional.bytes[1:5]
        self.dBm = -self.optional.bytes[5]
        self.sender = self.data.bytes[-5:-1]
        # Default to learn == True, as some devices don't have a learn button
        self.learn = True

        self.rorg = self.data.bytes[0]

        # parse learn bit and FUNC/TYPE, if applicable
        if self.rorg == RORG.BS1:
            self.learn = not self._bit_data[DB0.BIT_3]
        if self.rorg == RORG.BS4:
            self.learn = not self._bit_data[DB0.BIT_3]
            if self.learn:
                self.contains_eep = self._bit_data[DB0.BIT_7]
                if self.contains_eep:
                    # Get rorg_func and rorg_type from an unidirectional learn packet
                    self.rorg_func = self._bit_data[DB3.BIT_7:DB3.BIT_1].uint
                    self.rorg_type = self._bit_data[DB3.BIT_1:DB2.BIT_2].uint
                    self.rorg_manufacturer = self._bit_data[DB2.BIT_2:DB0.BIT_7].uint
                    self.logger.debug('learn received, EEP detected, RORG: 0x%02X, FUNC: 0x%02X, TYPE: 0x%02X, Manufacturer: 0x%02X' % (self.rorg, self.rorg_func, self.rorg_type, self.rorg_manufacturer))

        return super(RadioPacket, self).parse()


class UTETeachInPacket(RadioPacket):
    # Request types
    TEACH_IN = 0b00
    DELETE = 0b01
    NOT_SPECIFIC = 0b10

    # Response types
    NOT_ACCEPTED = [False, False]
    TEACHIN_ACCEPTED = [False, True]
    DELETE_ACCEPTED = [True, False]
    EEP_NOT_SUPPORTED = [True, True]

    unidirectional = False
    response_expected = False
    number_of_channels = 0xFF
    rorg_of_eep = RORG.UNDEFINED
    request_type = NOT_SPECIFIC
    channel = None

    contains_eep = True

    @property
    def bidirectional(self):
        return not self.unidirectional

    @property
    def teach_in(self):
        return self.request_type != self.DELETE

    @property
    def delete(self):
        return self.request_type == self.DELETE

    def parse(self):
        super(UTETeachInPacket, self).parse()
        self.unidirectional = not self._bit_data[DB6.BIT_7]
        self.response_expected = not self._bit_data[DB6.BIT_6]
        self.request_type = self._bit_data[DB6.BIT_5:DB6.BIT_3].uint
        self.rorg_manufacturer = (self._bit_data[DB3.BIT_2:DB2.BIT_7] + self._bit_data[DB4.BIT_7:DB3.BIT_7]).uint
        self.channel = self.data.bytes[2]
        self.rorg_type = self.data.bytes[5]
        self.rorg_func = self.data.bytes[6]
        self.rorg_of_eep = self.data.bytes[7]
        if self.teach_in:
            self.learn = True
        return self.parsed

    def create_response_packet(self, sender_id, response=TEACHIN_ACCEPTED):
        # Create data:
        # - Respond with same RORG (UTE Teach-in)
        # - Always use bidirectional communication, set response code, set command identifier.
        # - Databytes 5 to 0 are copied from the original message
        # - Set sender id and status
        data = [self.rorg] + \
               [0x81 | 0x20*response[0] | 0x10*response[1] ] + \
               list(self.data.bytes)[2:8] + \
               sender_id + [0]
            #[utils.from_bitarray([True, False] + response + [False, False, False, True])] + \

        # Always use 0x03 to indicate sending, attach sender ID, dBm, and security level
        optional = b'\x03' + self.sender + b'\xFF\x00'

        return RadioPacket(PACKET.RADIO_ERP1, data=bytes(data), optional=optional)


class ResponsePacket(Packet):
    response = 0
    response_data = []

    def parse(self):
        self.response = self.data.bytes[0]
        self.response_data = self.data.bytes[1:]
        return super(ResponsePacket, self).parse()


class EventPacket(Packet):
    event = 0
    event_data = []

    def parse(self):
        self.event = self.data.bytes[0]
        self.event_data = self.data.bytes[1:]
        return super(EventPacket, self).parse()
