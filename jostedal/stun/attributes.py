from jostedal.stun.agent import attribute, Address, Attribute
from jostedal import stun
import struct
import hmac
import hashlib
import binascii


@attribute
class MappedAddress(Address):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.1
    """

    type = stun.ATTR_MAPPED_ADDRESS
    _xored = False


@attribute
class Username(Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.3
    """

    type = stun.ATTR_USERNAME

    @classmethod
    def from_str(cls, msg, username):
        return cls(username.encode("utf8"))

    def __repr__(self, *args, **kwargs):
        return "USERNAME({!r})".format(str(self))


@attribute
class MessageIntegrity(Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.4
    """

    type = stun.ATTR_MESSAGE_INTEGRITY
    _struct = struct.Struct("20s")

    @classmethod
    def from_str(cls, msg, key):
        """
        :param key: H(A1) for long-term, SASLprep(password) for short-term auth
        """
        # HMAC covers the 'length' value of msg, so it needs to be updated first
        msg.length += cls._struct.size + Attribute.struct.size

        value = hmac.new(key, msg, hashlib.sha1).digest()
        return cls(value)

    def __repr__(self):
        return f"MESSAGE-INTEGRITY({self.hex()})"


@attribute
class ErrorCode(Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.6
    """

    type = stun.ATTR_ERROR_CODE
    _struct = struct.Struct(">2x2B")

    def __init__(self, data, err_class, err_number, reason):
        self.err_class = err_class
        self.err_number = err_number
        self.code = err_class * 100 + err_number
        self.reason = str(reason)

    @classmethod
    def from_buffer(cls, data, offset, length):
        err_class, err_number = cls._struct.unpack_from(data, offset)
        err_class &= 0b111
        value = memoryview(data)[offset : offset + length]
        reason = memoryview(value)[cls._struct.size :]
        return cls(value, err_class, err_number, reason)

    @classmethod
    def from_str(cls, msg, err_class, err_number, reason):
        value = cls._struct.pack(err_class, err_number)
        reason = reason.encode("utf8")
        return cls(value + reason, err_class, err_number, reason)

    def __repr__(self):
        return "ERROR-CODE(code={}, reason={!r})".format(self.code, self.reason)


@attribute
class UnknownAttributes(Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.9
    """

    type = stun.ATTR_UNKNOWN_ATTRIBUTES

    def __init__(self, data, types):
        self.types = types

    @classmethod
    def from_buffer(cls, data, offset, length):
        types = struct.unpack_from(">{}H".format(length // 2), data, offset)
        return cls(memoryview(data)[offset : offset + length], types)

    @classmethod
    def from_str(cls, msg, types):
        num = len(types)
        return cls(struct.pack(">{}H".format(num), *types), types)

    def __repr__(self):
        return "UNKNOWN-ATTRIBUTES({})".format(
            str(["{:#06x}".format(t) for t in self.types])
        )


@attribute
class Realm(Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.7
    """

    type = stun.ATTR_REALM

    @classmethod
    def from_str(cls, msg, realm):
        return cls(realm)

    def __repr__(self):
        return f"REALM({super().__repr__()})"


@attribute
class Nonce(Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.8
    """

    type = stun.ATTR_NONCE
    _max_length = 763  # less than 128 characters can be up to 763 bytes

    def __repr__(self):
        return f"NONCE({super().__repr__()})"


@attribute
class XorMappedAddress(Address):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.2
    """

    type = stun.ATTR_XOR_MAPPED_ADDRESS
    _xored = True


@attribute
class Software(Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.10
    """

    type = stun.ATTR_SOFTWARE

    @classmethod
    def from_str(cls, msg, software):
        return cls(software.encode("utf8"))

    def __repr__(self):
        return f"SOFTWARE({super().__repr__()})"


@attribute
class AlternateServer(Address):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.11
    """

    type = stun.ATTR_ALTERNATE_SERVER


@attribute
class Fingerprint(Attribute):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-15.5
    """

    type = stun.ATTR_FINGERPRINT
    _struct = struct.Struct(">L")
    _MAGIC = 0x5354554E

    @classmethod
    def from_str(cls, msg):
        # Checksum covers the 'length' value, so it needs to be updated first
        msg.length += cls._struct.size + Attribute.struct.size

        fingerprint = (binascii.crc32(msg) & 0xFFFFFFFF) ^ cls._MAGIC
        return cls(cls._struct.pack(fingerprint))

    @classmethod
    def from_buffer(cls, data, offset, length):
        (fingerprint,) = cls._struct.unpack_from(data, offset)
        return cls(memoryview(data)[offset : offset + length], fingerprint)

    def __repr__(self, *args, **kwargs):
        return f"FINGERPRINT(0x{self.hex()})"
