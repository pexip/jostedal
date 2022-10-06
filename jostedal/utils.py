import hashlib
import base64

from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC


def saslprep(string):
    # TODO
    return string


def ha1(username, realm, password):
    return hashlib.md5(
        ":".join((username, realm, saslprep(password))).encode()
    ).digest()


def secret_key(username, realm, password):
    """
    Generate passwords for Coturn REST api. See the "TURN REST API" section in
    README.turnserver in the coturn source code for algorithm details.
    """
    # Using sha1 because it's required by the TURN server API
    hmac = HMAC(password.encode(), hashes.SHA1(), backend)  # nosec
    hmac.update(username.encode())
    password = base64.b64encode(hmac.finalize()).decode("utf-8")

    return hashlib.md5(":".join((username, realm, password)).encode()).digest()
