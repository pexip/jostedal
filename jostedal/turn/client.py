from jostedal.stun.client import StunTcpClient, StunUdpClient, TransactionError
from jostedal import stun, turn
from jostedal.stun.agent import Message
from jostedal.turn import attributes
from jostedal.stun.authentication import LongTermCredentialMechanism
import logging


logger = logging.getLogger(__name__)


class TurnClientMixin(object):
    class UnAllocated():
        allocate = None

    class Allocating():
        _stun_allocate_success = None
        _stun_allocate_error = None

    class Allocated():
        refresh = None
        _stun_refresh_success = None
        _stun_refresh_error = None
        create_permission = None
        _stun_create_permission_success = None
        _stun_create_permission_error = None
        send = None
        _stun_data = None
        channel_bind = None
        _stun_channel_bind_success = None
        _stun_channel_bind_error = None

    class Expired(): pass

    def __init__(self, users):
        self.users = users
        self.turn_server_domain_name = None
        self.allocation = None

        self._handlers.update({
            # Allocate handlers
            (turn.METHOD_ALLOCATE, stun.CLASS_RESPONSE_SUCCESS):
                self._stun_allocate_success,
            (turn.METHOD_ALLOCATE, stun.CLASS_RESPONSE_ERROR):
                self._stun_allocate_error,
            # Refresh handlers
            (turn.METHOD_REFRESH, stun.CLASS_RESPONSE_SUCCESS):
                self._stun_refresh_success,
            (turn.METHOD_REFRESH, stun.CLASS_RESPONSE_ERROR):
                self._stun_refresh_error,
            # Data handlers
            (turn.METHOD_DATA, stun.CLASS_INDICATION):
                self._stun_data_indication,
            })

    def allocate(self, addr=None, transport=turn.TRANSPORT_UDP, time_to_expiry=None,
        dont_fragment=False, even_port=None, reservation_token=None):
        """
        :param even_port: None | 0 | 1 (1==reserve next highest port number)
        :see: http://tools.ietf.org/html/rfc5766#section-6.1
        """
        request = Message.encode(turn.METHOD_ALLOCATE, stun.CLASS_REQUEST)
        request.add_attr(attributes.RequestedTransport, transport)
        if time_to_expiry:
            request.add_attr(turn.ATTR_LIFETIME, time_to_expiry)
        if dont_fragment:
            request.add_attr(turn.ATTR_DONT_FRAGMENT)
        if even_port is not None and not reservation_token:
            request.add_attr(turn.ATTR_EVEN_PORT, even_port)
        if reservation_token:
            request.add_attr(turn.ATTR_RESERVATION_TOKEN, even_port)
        transaction = self.request(request, addr)
        return transaction

    def refresh(self, time_to_expiry):
        """
        :see: http://tools.ietf.org/html/rfc5766#section-6
        """
        request = Message.encode(turn.METHOD_REFRESH, stun.CLASS_REQUEST)
        if time_to_expiry:
            request.add_attr(turn.ATTR_LIFETIME, time_to_expiry)

    def get_host_transport_address(self):
        pass

    def get_server_transport_address(self):
        pass #dns srv record of "turn" or "turns"

    def _stun_allocate_success(self, msg, addr):
        transaction = self._transactions.get(msg.transaction_id)
        if transaction:
            relayed_addr = msg.get_attr(turn.ATTR_XOR_RELAYED_ADDRESS)
            if relayed_addr:
                transaction.succeed(str(relayed_addr))
            else:
                transaction.fail(TransactionError("No allocation in response"))

    def _stun_allocate_error(self, msg, addr):
        transaction = self._transactions.get(msg.transaction_id)
        if transaction:
            error_code = msg.get_attr(stun.ATTR_ERROR_CODE)
            if (error_code.code == 401 and
                    not isinstance(self.credential_mechanism, LongTermCredentialMechanism)):
                nonce = msg.get_attr(stun.ATTR_NONCE)
                realm = str(msg.get_attr(stun.ATTR_REALM))
                self.credential_mechanism = LongTermCredentialMechanism(realm, self.users)
                self.credential_mechanism.nonce = nonce
                logger.debug("Allocation failed: %s", error_code.reason)
                self.allocate(addr).chainDeferred(transaction)
            else:
                logger.error("Allocation failed: %s", error_code.reason)
                transaction.fail(TransactionError(error_code.reason))

    def _stun_refresh_success(self, msg, addr):
        self._stun_unhandled(msg, addr)

    def _stun_refresh_error(self, msg, addr):
        # If time_to_expiry == 0 and error 437 (Allocation Mismatch)
        # consider transaction a success
        self.errback(msg.format())

    def _stun_data_indication(self, msg, addr):
        self._stun_unhandled(msg, addr)


class TurnTcpClient(StunTcpClient, TurnClientMixin):
    def __init__(self, reactor, software, host, port, users):
        StunTcpClient.__init__(self, reactor, software, host, port)
        TurnClientMixin.__init__(self, users)


class TurnUdpClient(StunUdpClient, TurnClientMixin):
    def __init__(self, reactor, software, users):
        StunUdpClient.__init__(self, reactor, software)
        TurnClientMixin.__init__(self, users)
