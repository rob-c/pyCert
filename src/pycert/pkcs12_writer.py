"""A small, modern PKCS#12 writer.

``cryptography``/OpenSSL can serialise PKCS#12, but older versions (including
the newest release that supports Python 3.6) choose legacy PBE-SHA1-3DES and a
SHA-1 MAC.  The container format is simple and well specified, so pyCert builds
it itself and uses the library only for the primitives:

* PBES2 + PBKDF2-HMAC-SHA256 + AES-256-CBC for the key bag and for the
  encrypted SafeContents that contains it;
* an HMAC-SHA-256 (or SHA-1 for very old readers) integrity MAC over the
  AuthenticatedSafe;
* a friendlyName and localKeyID linking the key and leaf certificate.

Reading stays with ``cryptography``/OpenSSL, which also verifies the MAC and
parses files written by Java or older tools.
"""

import hashlib
import hmac as stdlib_hmac
import os

from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import asn1

DATA_OID = "1.2.840.113549.1.7.1"
ENCRYPTED_DATA_OID = "1.2.840.113549.1.7.6"
PBES2_OID = "1.2.840.113549.1.5.13"
PBKDF2_OID = "1.2.840.113549.1.5.12"
HMAC_SHA256_OID = "1.2.840.113549.2.9"
HMAC_SHA1_OID = "1.2.840.113549.2.7"
AES256_CBC_OID = "2.16.840.1.101.3.4.1.42"
CERT_BAG_OID = "1.2.840.113549.1.12.10.1.3"
PKCS8_SHROUDED_KEY_BAG_OID = "1.2.840.113549.1.12.10.1.2"
X509_CERTIFICATE_OID = "1.2.840.113549.1.9.22.1"
FRIENDLY_NAME_OID = "1.2.840.113549.1.9.20"
LOCAL_KEY_ID_OID = "1.2.840.113549.1.9.21"
SHA256_OID = "2.16.840.1.101.3.4.2.1"
SHA1_OID = "1.3.14.3.2.26"

DEFAULT_ITERATIONS = 100000
DEFAULT_MAC_ITERATIONS = 20000


def _hash_algorithm(name):
    if name == "sha256":
        return hashlib.sha256, SHA256_OID, 32
    if name == "sha1":
        return hashlib.sha1, SHA1_OID, 20
    raise ValueError("unsupported MAC hash: %s" % name)


def _bmp_password(password):
    # PKCS#12 KDF uses a BMPString with a null terminator.
    return password.encode("utf-16-be") + b"\x00\x00"


def _repeat_to_block(value, block_size):
    """Repeat *value* to the next multiple of the block size (final copy truncated)."""
    if not value:
        return b""
    output_length = block_size * ((len(value) + block_size - 1) // block_size)
    repeats = (output_length + len(value) - 1) // len(value)
    return (value * repeats)[:output_length]


def pkcs12_kdf(password, salt, purpose, iterations, length, hash_name="sha256"):
    """RFC 7292 appendix B.2 key derivation.

    ``password`` must already be the BMPString bytes used by PKCS#12 (see
    :func:`_bmp_password`); this keeps the function usable for known-answer
    tests of the KDF itself.
    """
    hash_function, _oid, u = _hash_algorithm(hash_name)
    v = 64  # SHA-1 and SHA-256 both use 64-byte blocks
    diversifier = bytes((purpose,)) * v
    salt_block = _repeat_to_block(salt or b"", v)
    password_block = _repeat_to_block(password, v)
    material = salt_block + password_block
    result = b""
    while len(result) < length:
        digest = diversifier + material
        for _ in range(iterations):
            digest = hash_function(digest).digest()
        block = (digest * (v // u + 1))[:v]
        updated = bytearray()
        for offset in range(0, len(material), v):
            number = int.from_bytes(material[offset : offset + v], "big")
            number = (number + int.from_bytes(block, "big") + 1) % (1 << (8 * v))
            updated += number.to_bytes(v, "big")
        material = bytes(updated)
        result += digest
    return result[:length]


def _pbes2_encrypt(plaintext, password, iterations):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = PBKDF2HMAC(
        algorithm=__import__("cryptography").hazmat.primitives.hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    ).derive(password.encode("utf-8"))
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    kdf_params = asn1.seq(
        asn1.oid(PBKDF2_OID),
        asn1.seq(
            asn1.octet_string(salt),
            asn1.integer(iterations),
            asn1.seq(asn1.oid(HMAC_SHA256_OID), asn1.null()),
        ),
    )
    encryption_params = asn1.seq(asn1.oid(AES256_CBC_OID), asn1.octet_string(iv))
    algorithm = asn1.seq(asn1.oid(PBES2_OID), asn1.seq(kdf_params, encryption_params))
    return algorithm, ciphertext


def _attributes(friendly_name, local_key_id=None):
    attributes = []
    if friendly_name:
        attributes.append(asn1.seq(asn1.oid(FRIENDLY_NAME_OID), asn1.set_of(asn1.bmp_string(friendly_name))))
    if local_key_id is not None:
        attributes.append(asn1.seq(asn1.oid(LOCAL_KEY_ID_OID), asn1.set_of(asn1.octet_string(local_key_id))))
    return asn1.set_of(*attributes) if attributes else b""


def _certificate_bag(certificate, friendly_name, local_key_id, with_key_id):
    der = certificate.public_bytes(serialization.Encoding.DER)
    cert_bag = asn1.seq(asn1.oid(X509_CERTIFICATE_OID), asn1.explicit(0, asn1.octet_string(der)))
    return asn1.seq(
        asn1.oid(CERT_BAG_OID),
        asn1.explicit(0, cert_bag),
        _attributes(friendly_name, local_key_id if with_key_id else None),
    )


def _key_bag(key, password, iterations, friendly_name, local_key_id):
    key_der = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    algorithm, ciphertext = _pbes2_encrypt(key_der, password, iterations)
    encrypted_private_key = asn1.seq(algorithm, asn1.octet_string(ciphertext))
    return asn1.seq(
        asn1.oid(PKCS8_SHROUDED_KEY_BAG_OID),
        asn1.explicit(0, encrypted_private_key),
        _attributes(friendly_name, local_key_id),
    )


def encode_pkcs12(
    key,
    certificate,
    chain=(),
    password="",
    friendly_name="",
    iterations=DEFAULT_ITERATIONS,
    mac_iterations=DEFAULT_MAC_ITERATIONS,
    mac_hash="sha256",
):
    """Return the DER encoding of a PKCS#12 PFX containing key, leaf and chain."""
    if not password:
        raise ValueError("password required")
    if iterations < 1 or mac_iterations < 1:
        raise ValueError("iteration counts must be positive")
    hash_function, mac_oid, mac_length = _hash_algorithm(mac_hash)

    chain = list(chain or [])
    local_key_id = hashlib.sha1(certificate.public_bytes(serialization.Encoding.DER)).digest()

    # Certificate bags (leaf first, then issuers), unencrypted inside the
    # AuthenticatedSafe as is conventional.
    cert_bags = [_certificate_bag(certificate, friendly_name, local_key_id, with_key_id=True)]
    for index, issuer in enumerate(chain):
        cert_bags.append(
            _certificate_bag(
                issuer,
                "%s-issuer-%d" % (friendly_name or "certificate", index + 1),
                None,
                with_key_id=False,
            )
        )
    cert_safe_contents = asn1.seq(*cert_bags)
    cert_content_info = asn1.seq(asn1.oid(DATA_OID), asn1.explicit(0, asn1.octet_string(cert_safe_contents)))

    # The key lives in a shrouded bag inside an extra encrypted SafeContents.
    key_safe_contents = asn1.seq(_key_bag(key, password, iterations, friendly_name, local_key_id))
    algorithm, encrypted_contents = _pbes2_encrypt(key_safe_contents, password, iterations)
    encrypted_content_info = asn1.seq(asn1.oid(DATA_OID), algorithm, asn1.implicit(0, encrypted_contents))
    encrypted_data = asn1.seq(asn1.integer(0), encrypted_content_info)
    key_content_info = asn1.seq(asn1.oid(ENCRYPTED_DATA_OID), asn1.explicit(0, encrypted_data))

    authenticated_safe = asn1.seq(cert_content_info, key_content_info)
    auth_safe = asn1.seq(asn1.oid(DATA_OID), asn1.explicit(0, asn1.octet_string(authenticated_safe)))

    # Integrity MAC over the AuthenticatedSafe contents (RFC 7292, 4).
    mac_salt = os.urandom(16)
    mac_key = pkcs12_kdf(_bmp_password(password), mac_salt, 3, mac_iterations, mac_length, mac_hash)
    mac = stdlib_hmac.new(mac_key, authenticated_safe, hash_function).digest()
    mac_parts = [
        asn1.seq(asn1.seq(asn1.oid(mac_oid), asn1.null()), asn1.octet_string(mac)),
        asn1.octet_string(mac_salt),
    ]
    if mac_iterations != 1:
        # MacData.iterations has DEFAULT 1 and DER omits default values.
        mac_parts.append(asn1.integer(mac_iterations))
    mac_data = asn1.seq(*mac_parts)
    return asn1.seq(asn1.integer(3), auth_safe, mac_data)
