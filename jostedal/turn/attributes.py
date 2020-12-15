import struct
from jostedal.stun.agent import attribute, Address, Attribute
from jostedal import turn


@attribute
class ChannelNumber(Attribute):
    """TURN STUN CHANNEL-NUMBER attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.1
    """
    type = turn.ATTR_CHANNEL_NUMBER
    _struct = struct.Struct('>H2x')

    def __init__(self, data, channel_number):
        self.channel_number = channel_number

    @classmethod
    def decode(cls, data, offset, length):
        channel_number = struct.unpack_from('>H2x', data, offset)
        return cls(buffer(data, offset, length), channel_number)

    @classmethod
    def encode(cls, data, channel_number):
        return cls(cls._struct.pack(channel_number), channel_number)

    def __repr__(self):
        return "CHANNEL-NUMBER(channel-number={})".format(self.channel_number)


@attribute
class Lifetime(Attribute):
    """TURN STUN LIFETIME attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.2
    """
    type = turn.ATTR_LIFETIME
    _struct = struct.Struct('>L')

    def __init__(self, data, time_to_expiry):
        self.time_to_expiry = time_to_expiry

    @classmethod
    def decode(cls, data, offset, length):
        lifetime, = cls._struct.unpack_from(data, offset)
        return cls(buffer(data, offset, length), lifetime)

    @classmethod
    def encode(cls, msg, time_to_expiry):
        return cls(cls._struct.pack(time_to_expiry), time_to_expiry)

    def __repr__(self):
        return "LIFETIME(time-to-expiry={})".format(self.time_to_expiry)


@attribute
class XorPeerAddress(Address):
    """TURN STUN XOR-PEER-ADDRESS attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.3
    """
    type = turn.ATTR_XOR_PEER_ADDRESS
    _xored = True


@attribute
class Data(Attribute):
    """TURN STUN DATA attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.4
    """
    type = turn.ATTR_DATA

    def __repr__(self):
        return "DATA(length={})".format(len(self))


@attribute
class XorRelayedAddress(Address):
    """TURN STUN XOR-RELAYED-ADDRESS attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.5
    """
    type = turn.ATTR_XOR_RELAYED_ADDRESS
    _xored = True


@attribute
class EvenPort(Attribute):
    """TURN STUN EVEN-PORT attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.6
    """
    type = turn.ATTR_EVEN_PORT
    RESERVE = 0b10000000

    @classmethod
    def decode(cls, data, offset, length):
        return struct.unpack_from('>B', data, offset)[0] & 0b10000000


@attribute
class RequestedTransport(Attribute):
    """TURN STUN REQUESTED-TRANSPORT attribute
    :see: http://tools.ietf.org/html/rfc5766#section-14.7
    """
    type = turn.ATTR_REQUESTED_TRANSPORT
    _struct = struct.Struct('>B3x')

    def __init__(self, data, protocol):
        self.protocol = protocol

    @classmethod
    def encode(cls, msg, protocol):
        return cls(cls._struct.pack(protocol), protocol)

    @classmethod
    def decode(cls, data, offset, length):
        protocol, = cls._struct.unpack_from(data, offset)
        return cls(buffer(data, offset, length), protocol)

    def __repr__(self, *args, **kwargs):
        return "REQUESTED-TRANSPORT({:#02x})".format(self.protocol)


@attribute
class DontFragment(Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5766#section-14.8
    """
    type = turn.ATTR_DONT_FRAGMENT


@attribute
class ReservationToken(Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5766#section-14.9
    """
    type = turn.ATTR_RESERVATION_TOKEN

@attribute
class ConnectionId(Attribute):
    """TURN CONNECTION_ID attribute
    :see: http://tools.ietf.org/html/rfc6062#section-6.2
    """
    type = turn.ATTR_CONNECTION_ID
    _struct = struct.Struct('>L')

    def __init__(self, data, connection_id):
        self.connection_id = connection_id

    @classmethod
    def decode(cls, data, offset, length):
        connection_id, = cls._struct.unpack_from(data, offset)
        return cls(buffer(data, offset, length), connection_id)

    @classmethod
    def encode(cls, msg, connection_id):
        return cls(cls._struct.pack(connection_id), connection_id)

    def __repr__(self):
        return "CONNECTION_ID(connection-id={})".format(self.connection_id)
