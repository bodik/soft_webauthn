"""
Module implementing software webauthn token for testing webauthn enabled
applications
"""

import json
import os
from base64 import urlsafe_b64encode
from enum import Enum
from struct import pack

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.cose import ES256
from fido2.webauthn import AttestedCredentialData
from fido2.utils import sha256


# https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data
class AuthenticatorDataFlags(Enum):
    """
    Values for authenticator data flags
    """

    USER_PRESENT = (1 << 0)
    RESERVED1 = (1 << 1)
    USER_VERIFIED = (1 << 2)
    BACKUP_ELIGIBLE = (1 << 3)
    BACKED_UP = (1 << 4)
    RESERVED2 = (1 << 5)
    ATTESTED_CREDENTIAL_DATA_INCLUDED = (1 << 6)
    EXTENSION_DATA_INCLUDED = (1 << 7)


class SoftWebauthnDevice():
    """
    This simulates the Webauthn browser API with a authenticator device
    connected. It's primary use-case is testing, device can hold only
    one credential.
    """

    def __init__(self):
        self.credential_id = None
        self.private_key = None
        self.aaguid = b'\x00' * 16
        self.rp_id = None
        self.user_handle = None
        self.sign_count = 0

    @staticmethod
    def convert_flags(flags):
        """Converts flag-like values into final binary representation"""

        result = 0
        for flag in flags:
            if isinstance(flag, AuthenticatorDataFlags):
                value = flag.value
            elif isinstance(flag, int):
                if flag > (1 << 7):
                    raise ValueError(f"Invalid flag value {flag}")
                value = flag
            else:
                raise ValueError(
                    f"Flag can either be an integer or an instance of AuthenticatorDataFlags. "
                    f"{flag} was provided, which is {type(flag)}"
                )

            result |= value

        return result.to_bytes(1, "little")

    def cred_init(self, rp_id, user_handle):
        """initialize credential for rp_id under user_handle"""

        self.credential_id = os.urandom(32)
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.rp_id = rp_id
        self.user_handle = user_handle

    def cred_as_attested(self):
        """return current credential as AttestedCredentialData"""

        return AttestedCredentialData.create(
            self.aaguid,
            self.credential_id,
            ES256.from_cryptography_key(self.private_key.public_key()))

    def create(self, options, origin, flags=None):
        """create credential and return PublicKeyCredential object aka attestation"""

        if flags is None:
            flags = [AuthenticatorDataFlags.ATTESTED_CREDENTIAL_DATA_INCLUDED, AuthenticatorDataFlags.USER_PRESENT]

        flags = self.convert_flags(flags)

        if {'alg': -7, 'type': 'public-key'} not in options['publicKey']['pubKeyCredParams']:
            raise ValueError('Requested pubKeyCredParams does not contain supported type')

        if ('attestation' in options['publicKey']) and (options['publicKey']['attestation'] not in [None, 'none']):
            raise ValueError('Only none attestation supported')

        # prepare new key
        self.cred_init(options['publicKey']['rp']['id'], options['publicKey']['user']['id'])

        # generate credential response
        client_data = {
            'type': 'webauthn.create',
            'challenge': urlsafe_b64encode(options['publicKey']['challenge']).decode('ascii').rstrip('='),
            'origin': origin
        }

        rp_id_hash = sha256(self.rp_id.encode('ascii'))
        sign_count = pack('>I', self.sign_count)
        credential_id_length = pack('>H', len(self.credential_id))
        cose_key = cbor.encode(ES256.from_cryptography_key(self.private_key.public_key()))
        attestation_object = {
            'authData':
                rp_id_hash + flags + sign_count
                + self.aaguid + credential_id_length + self.credential_id + cose_key,
            'fmt': 'none',
            'attStmt': {}
        }

        return {
            'id': urlsafe_b64encode(self.credential_id),
            'rawId': self.credential_id,
            'response': {
                'clientDataJSON': json.dumps(client_data).encode('utf-8'),
                'attestationObject': cbor.encode(attestation_object)
            },
            'type': 'public-key'
        }

    def get(self, options, origin, flags=None):
        """get authentication credential aka assertion"""

        if flags is None:
            flags = [AuthenticatorDataFlags.USER_PRESENT]

        flags = self.convert_flags(flags)

        if self.rp_id != options['publicKey']['rpId']:
            raise ValueError('Requested rpID does not match current credential')

        self.sign_count += 1

        # prepare signature
        client_data = json.dumps({
            'type': 'webauthn.get',
            'challenge': urlsafe_b64encode(options['publicKey']['challenge']).decode('ascii').rstrip('='),
            'origin': origin
        }).encode('utf-8')
        client_data_hash = sha256(client_data)

        rp_id_hash = sha256(self.rp_id.encode('ascii'))
        sign_count = pack('>I', self.sign_count)
        authenticator_data = rp_id_hash + flags + sign_count

        signature = self.private_key.sign(authenticator_data + client_data_hash, ec.ECDSA(hashes.SHA256()))

        # generate assertion
        return {
            'id': urlsafe_b64encode(self.credential_id),
            'rawId': self.credential_id,
            'response': {
                'authenticatorData': authenticator_data,
                'clientDataJSON': client_data,
                'signature': signature,
                'userHandle': self.user_handle
            },
            'type': 'public-key'
        }
