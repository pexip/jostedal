from jostedal.utils import saslprep, ha1, secret_key
from jostedal.stun import attributes

import os
import logging
from datetime import datetime


logger = logging.getLogger(__name__)


class CredentialMechanism(object):
    def update(self, message):
        pass


class ShortTermCredentialMechanism(CredentialMechanism):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-10.1
    """

    def __init__(self, username, password):
        self.username = username
        self.hmac_key = saslprep(password)

    def update(self, msg):
        msg.add_attr(attributes.Username, self.username)
        msg.add_attr(attributes.MessageIntegrity, self.hmac_key)


class LongTermCredentialMechanism(CredentialMechanism):
    """
    :see: http://tools.ietf.org/html/rfc5389#section-10.2
    """

    def __init__(self, realm, users):
        self.nonce = self.generate_nonce()
        self.realm = realm
        self.hmac_keys = {}
        self.credential_type = "namepsw"
        for username, credentials in users.items():
            key = credentials.get("key")
            if not key:
                password = credentials.get("password")
                if not password:
                    logger.warning("Invalid credentials for %s", username)
                    continue

                self.hmac_keys[username] = ha1(username, self.realm, password)
            else:
                self.credential_type = "shared_secret"
                self.key = key

    def add_user(self, username, password):
        self.hmac_keys[username] = ha1(username, self.realm, password)

    def add_key_user(self, username):

        if self.credential_type != "shared_secret":
            return

        username = username.decode("utf-8")

        passw = secret_key(username, self.realm, self.key)
        self.hmac_keys[username] = passw

        try:
            expiry, _uuid = username.split(":")
            expiry = int(expiry)
        except ValueError:
            logger.warning("Invalid credentials for %s", username)
            return

        if expiry < datetime.now().timestamp():
            logger.warning("User credentials expired for %s", username)
            return

        self.hmac_keys[username] = passw

    def generate_nonce(self, length=16):
        return os.urandom(length // 2).hex()

    def update(self, msg):
        msg.add_attr(attributes.Nonce, self.nonce.encode())
        msg.add_attr(attributes.Realm, self.realm.encode())
        msg.add_attr(attributes.MessageIntegrity, list(self.hmac_keys.values())[0])

    def __str__(self):
        return "realm={}".format(self.realm)

    def __repr__(self, *args, **kwargs):
        return "LongTermCredentialMechanism({})".format(self)
