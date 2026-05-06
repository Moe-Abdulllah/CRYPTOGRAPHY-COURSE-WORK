#!/usr/bin/env python3
"""
IoT lightweight crypto prototype using Ascon-AEAD128 (NIST SP 800-232).

- Associated Data (AD): header/metadata authenticated but not encrypted
- Plaintext: sensor payload encrypted + authenticated
- Output: ciphertext + tag

Code provenance:
- Ascon Python implementation: https://github.com/meichlseder/pyascon (ascon.py)
"""

import os
import struct

import ascon  # from the cloned pyascon repo
print("Using ascon from:", ascon.__file__)

def build_iot_header(device_id: int, msg_counter: int) -> bytes:
    """
    Example IoT header as Associated Data (AD).
    Keep it small and deterministic: device_id (4 bytes) + counter (8 bytes).
    """
    return struct.pack(">IQ", device_id & 0xFFFFFFFF, msg_counter & 0xFFFFFFFFFFFFFFFF)


def encrypt_iot_message(key: bytes, nonce: bytes, ad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Returns (ciphertext, tag).
    Ascon-AEAD128 uses:
      - 128-bit key
      - 128-bit nonce
      - 128-bit tag
    """
    if len(key) != 16:
        raise ValueError("Ascon-AEAD128 requires a 16-byte (128-bit) key")
    if len(nonce) != 16:
        raise ValueError("Ascon-AEAD128 requires a 16-byte (128-bit) nonce")

    # pyascon API: ascon_aead_encrypt(key, nonce, associateddata, plaintext, variant)
    # Variant string naming is defined by the library.
    ciphertext, tag = ascon.ascon_encrypt(key, nonce, ad, plaintext, "Ascon-AEAD128")
    return ciphertext, tag


def decrypt_iot_message(key: bytes, nonce: bytes, ad: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """
    Returns plaintext if tag verifies; raises ValueError (or returns None depending on impl) on failure.
    """
    plaintext = ascon.ascon_aead_decrypt(key, nonce, ad, ciphertext, tag, "Ascon-AEAD128")
    if plaintext is None:
        # Some implementations return None on authentication failure
        raise ValueError("Authentication failed (tag mismatch)")
    return plaintext


def main():
    # ---- Key management (prototype) ----
    # In a real device, key comes from secure provisioning / secure element.
    key = os.urandom(16)

    # Nonce must be unique per message under a given key.
    # A simple prototype nonce: 16 random bytes (for real IoT prefer counter-based uniqueness).
    nonce = os.urandom(16)

    # ---- Associated Data (AD) = IoT header ----
    device_id = 0x10203040
    msg_counter = 1
    ad = build_iot_header(device_id, msg_counter)

    # ---- Payload (plaintext) ----
    plaintext = b"temp_c=23.50;humidity=41.2"

    print("AD (header)      :", ad.hex())
    print("Plaintext        :", plaintext)

    # Encrypt
    ciphertext, tag = encrypt_iot_message(key, nonce, ad, plaintext)
    print("Nonce            :", nonce.hex())
    print("Ciphertext       :", ciphertext.hex())
    print("Tag              :", tag.hex())

    # Decrypt (verify)
    recovered = decrypt_iot_message(key, nonce, ad, ciphertext, tag)
    print("Recovered        :", recovered)

    # ---- Negative test: tamper with ciphertext ----
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01  # flip one bit
    try:
        decrypt_iot_message(key, nonce, ad, bytes(tampered), tag)
        print("ERROR: tampering was not detected (unexpected)")
    except ValueError as e:
        print("Tamper test OK   :", str(e))


if __name__ == "__main__":
    main()
