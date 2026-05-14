#!/usr/bin/env python3
import time
import tracemalloc
import os
import hmac


debug = False
debugpermutation = False

def ascon_encrypt(key, nonce, associateddata, plaintext, variant="Ascon-128"):
    """
    returns ciphertext||tag (tag is 16 bytes)
    """
    assert variant in ["Ascon-128", "Ascon-128a", "Ascon-80pq"]
    if variant in ["Ascon-128", "Ascon-128a"]:
        assert len(key) == 16 and len(nonce) == 16
    if variant == "Ascon-80pq":
        assert len(key) == 20 and len(nonce) == 16

    S = [0, 0, 0, 0, 0]
    k = len(key) * 8
    a = 12
    b = 8 if variant == "Ascon-128a" else 6
    rate = 16 if variant == "Ascon-128a" else 8

    ascon_initialize(S, k, rate, a, b, key, nonce)
    ascon_process_associated_data(S, b, rate, associateddata)
    ciphertext = ascon_process_plaintext(S, b, rate, plaintext)
    tag = ascon_finalize(S, rate, a, key)
    return ciphertext + tag


def ascon_decrypt(key, nonce, associateddata, ciphertext_and_tag, variant="Ascon-128"):
    """
    returns plaintext bytes or None if verification fails
    """
    assert variant in ["Ascon-128", "Ascon-128a", "Ascon-80pq"]
    if variant in ["Ascon-128", "Ascon-128a"]:
        assert len(key) == 16 and len(nonce) == 16 and len(ciphertext_and_tag) >= 16
    if variant == "Ascon-80pq":
        assert len(key) == 20 and len(nonce) == 16 and len(ciphertext_and_tag) >= 16

    ct = ciphertext_and_tag[:-16]
    tag = ciphertext_and_tag[-16:]

    S = [0, 0, 0, 0, 0]
    k = len(key) * 8
    a = 12
    b = 8 if variant == "Ascon-128a" else 6
    rate = 16 if variant == "Ascon-128a" else 8

    ascon_initialize(S, k, rate, a, b, key, nonce)
    ascon_process_associated_data(S, b, rate, associateddata)
    plaintext = ascon_process_ciphertext(S, b, rate, ct)
    comp_tag = ascon_finalize(S, rate, a, key)

    # constant-time tag check
    if hmac.compare_digest(comp_tag, tag):
        return plaintext
    return None


def ascon_initialize(S, k, rate, a, b, key, nonce):
    iv_zero_key_nonce = to_bytes([k, rate * 8, a, b] + (20 - len(key)) * [0]) + key + nonce
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(iv_zero_key_nonce)

    ascon_permutation(S, a)

    zero_key = bytes_to_state(zero_bytes(40 - len(key)) + key)
    S[0] ^= zero_key[0]
    S[1] ^= zero_key[1]
    S[2] ^= zero_key[2]
    S[3] ^= zero_key[3]
    S[4] ^= zero_key[4]


def ascon_process_associated_data(S, b, rate, associateddata):
    if len(associateddata) > 0:
        a_zeros = rate - (len(associateddata) % rate) - 1
        a_padding = to_bytes([0x80] + [0 for _ in range(a_zeros)])
        a_padded = associateddata + a_padding

        for block in range(0, len(a_padded), rate):
            S[0] ^= bytes_to_int(a_padded[block:block + 8])
            if rate == 16:
                S[1] ^= bytes_to_int(a_padded[block + 8:block + 16])
            ascon_permutation(S, b)

    # domain separation
    S[4] ^= 1


def ascon_process_plaintext(S, b, rate, plaintext):
    p_lastlen = len(plaintext) % rate
    p_padding = to_bytes([0x80] + (rate - p_lastlen - 1) * [0x00])
    p_padded = plaintext + p_padding

    ciphertext = to_bytes([])
    for block in range(0, len(p_padded) - rate, rate):
        if rate == 8:
            S[0] ^= bytes_to_int(p_padded[block:block + 8])
            ciphertext += int_to_bytes(S[0], 8)
        else:  # rate == 16
            S[0] ^= bytes_to_int(p_padded[block:block + 8])
            S[1] ^= bytes_to_int(p_padded[block + 8:block + 16])
            ciphertext += int_to_bytes(S[0], 8) + int_to_bytes(S[1], 8)

        ascon_permutation(S, b)

    block = len(p_padded) - rate
    if rate == 8:
        S[0] ^= bytes_to_int(p_padded[block:block + 8])
        ciphertext += int_to_bytes(S[0], 8)[:p_lastlen]
    else:  # rate == 16
        S[0] ^= bytes_to_int(p_padded[block:block + 8])
        S[1] ^= bytes_to_int(p_padded[block + 8:block + 16])
        ciphertext += (
            int_to_bytes(S[0], 8)[:min(8, p_lastlen)] +
            int_to_bytes(S[1], 8)[:max(0, p_lastlen - 8)]
        )

    return ciphertext


def ascon_process_ciphertext(S, b, rate, ciphertext):
    c_lastlen = len(ciphertext) % rate
    c_padded = ciphertext + zero_bytes(rate - c_lastlen)

    plaintext = to_bytes([])
    for block in range(0, len(c_padded) - rate, rate):
        if rate == 8:
            Ci = bytes_to_int(c_padded[block:block + 8])
            plaintext += int_to_bytes(S[0] ^ Ci, 8)
            S[0] = Ci
        else:  # rate == 16
            Ci0 = bytes_to_int(c_padded[block:block + 8])
            Ci1 = bytes_to_int(c_padded[block + 8:block + 16])
            plaintext += int_to_bytes(S[0] ^ Ci0, 8) + int_to_bytes(S[1] ^ Ci1, 8)
            S[0] = Ci0
            S[1] = Ci1

        ascon_permutation(S, b)

    block = len(c_padded) - rate
    if rate == 8:
        c_padding1 = (0x80 << ((rate - c_lastlen - 1) * 8))
        c_mask = (0xFFFFFFFFFFFFFFFF >> (c_lastlen * 8))
        Ci = bytes_to_int(c_padded[block:block + 8])
        plaintext += int_to_bytes(Ci ^ S[0], 8)[:c_lastlen]
        S[0] = Ci ^ (S[0] & c_mask) ^ c_padding1
    else:  # rate == 16
        c_lastlen_word = c_lastlen % 8
        c_padding1 = (0x80 << ((8 - c_lastlen_word - 1) * 8))
        c_mask = (0xFFFFFFFFFFFFFFFF >> (c_lastlen_word * 8))
        Ci0 = bytes_to_int(c_padded[block:block + 8])
        Ci1 = bytes_to_int(c_padded[block + 8:block + 16])
        plaintext += (int_to_bytes(S[0] ^ Ci0, 8) + int_to_bytes(S[1] ^ Ci1, 8))[:c_lastlen]
        if c_lastlen < 8:
            S[0] = Ci0 ^ (S[0] & c_mask) ^ c_padding1
        else:
            S[0] = Ci0
            S[1] = Ci1 ^ (S[1] & c_mask) ^ c_padding1

    return plaintext


def ascon_finalize(S, rate, a, key):
    assert len(key) in [16, 20]
    S[rate // 8 + 0] ^= bytes_to_int(key[0:8])
    S[rate // 8 + 1] ^= bytes_to_int(key[8:16])
    S[rate // 8 + 2] ^= bytes_to_int(key[16:] + zero_bytes(24 - len(key)))

    ascon_permutation(S, a)

    S[3] ^= bytes_to_int(key[-16:-8])
    S[4] ^= bytes_to_int(key[-8:])
    return int_to_bytes(S[3], 8) + int_to_bytes(S[4], 8)


def ascon_permutation(S, rounds=1):
    assert rounds <= 12
    for r in range(12 - rounds, 12):
        # add round constants
        S[2] ^= (0xF0 - r * 0x10 + r * 0x01)

        # substitution layer
        S[0] ^= S[4]
        S[4] ^= S[3]
        S[2] ^= S[1]
        T = [((S[i] ^ 0xFFFFFFFFFFFFFFFF) & S[(i + 1) % 5]) for i in range(5)]
        for i in range(5):
            S[i] ^= T[(i + 1) % 5]
        S[1] ^= S[0]
        S[0] ^= S[4]
        S[3] ^= S[2]
        S[2] ^= 0xFFFFFFFFFFFFFFFF

        # linear diffusion layer
        S[0] ^= rotr(S[0], 19) ^ rotr(S[0], 28)
        S[1] ^= rotr(S[1], 61) ^ rotr(S[1], 39)
        S[2] ^= rotr(S[2],  1) ^ rotr(S[2],  6)
        S[3] ^= rotr(S[3], 10) ^ rotr(S[3], 17)
        S[4] ^= rotr(S[4],  7) ^ rotr(S[4], 41)


# ---------- helper functions ----------
def get_random_bytes(num):
    return os.urandom(num)

def zero_bytes(n):
    return n * b"\x00"

def to_bytes(l):
    return bytes(bytearray(l))

def bytes_to_int(b):
    bb = to_bytes(b)
    return sum([bi << ((len(bb) - 1 - i) * 8) for i, bi in enumerate(bb)])

def bytes_to_state(b):
    return [bytes_to_int(b[8*w:8*(w+1)]) for w in range(5)]

def int_to_bytes(integer, nbytes):
    return to_bytes([(integer >> ((nbytes - 1 - i) * 8)) & 0xFF for i in range(nbytes)])

def rotr(val, r):
    # 64-bit rotate-right
    val &= 0xFFFFFFFFFFFFFFFF
    return ((val >> r) | (val << (64 - r))) & 0xFFFFFFFFFFFFFFFF


# ============================================================
# Evaluation suite 
# ============================================================

def run_evaluation():
    print("==============================================")
    print("      ASCON AEAD EVALUATION     ")
    print("==============================================\n")

    # Choose variant:
    # - "Ascon-128a" => rate=16, b=8 (commonly associated with NIST AEAD128 parameter set)
    # - "Ascon-128"  => rate=8,  b=6 (older Ascon-128 parameter set)
    variant = "Ascon-128"

    # Deterministic test key/nonce as bytes
    # (In real use: DO NOT reuse (key, nonce) pairs.)
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    nonce = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    plaintext = b"MY NAME IS MOHAMMED"
    ad = b"PROFF BILL IS THE BEST LECTURER"

    # --- 1. VALIDATION ---
    print("[1] Validation Check (Encrypt/Decrypt + Tag Verify + AD binding)")
    ct_and_tag = ascon_encrypt(key, nonce, ad, plaintext, variant=variant)
    decrypted = ascon_decrypt(key, nonce, ad, ct_and_tag, variant=variant)

    print(f"    Variant:       {variant}")
    print(f"    Plaintext:     {plaintext!r}")
    print(f"    AD (hex):      {ad.hex()}")
    print(f"    CT||TAG (hex): {ct_and_tag.hex()}")
    print(f"    Decrypted:     {decrypted!r}")
    print(f"    Status:        {'SUCCESS' if decrypted == plaintext else 'FAIL'}\n")

    # Tamper test (flip a bit)
    tampered = bytearray(ct_and_tag)
    tampered[0] ^= 1
    tampered_out = ascon_decrypt(key, nonce, ad, bytes(tampered), variant=variant)
    print("    Tamper test:   ", "PASS (rejected)" if tampered_out is None else "FAIL (accepted)")

    # AD binding test
    bad_ad = ad + b"x"
    bad_ad_out = ascon_decrypt(key, nonce, bad_ad, ct_and_tag, variant=variant)
    print("    AD binding:    ", "PASS (rejected)" if bad_ad_out is None else "FAIL (accepted)")
    print()

    # --- 2. EXECUTION TIME & THROUGHPUT (ENCRYPTION) ---
    print("[2] Throughput & Timing (Encryption)")
    iterations = 2000

    start_time = time.perf_counter()
    for _ in range(iterations):
        # For a benchmark, we keep nonce constant to avoid extra overhead;
        # for real security you must NOT reuse nonces with the same key.
        ascon_encrypt(key, nonce, ad, plaintext, variant=variant)
    end_time = time.perf_counter()
    duration = end_time - start_time

    total_bytes = iterations * len(plaintext)
    kb_processed = total_bytes / 1024
    throughput = kb_processed / duration if duration > 0 else float("inf")

    print(f"    Messages:        {iterations}")
    print(f"    Payload bytes:   {len(plaintext)}")
    print(f"    Total Time:      {duration:.4f} seconds")
    print(f"    Avg Latency:     {(duration/iterations)*1e3:.3f} ms/message")
    print(f"    Throughput:      {throughput:.2f} KB/s\n")

    # --- 2b. DECRYPTION TIMING ---
    print("[2b] Throughput & Timing (Decryption + Tag Verify)")
    start_time = time.perf_counter()
    for _ in range(iterations):
        out = ascon_decrypt(key, nonce, ad, ct_and_tag, variant=variant)
        if out is None:
            raise RuntimeError("Unexpected auth failure in timing test")
    end_time = time.perf_counter()
    duration_dec = end_time - start_time

    throughput_dec = kb_processed / duration_dec if duration_dec > 0 else float("inf")
    print(f"    Messages:        {iterations}")
    print(f"    Total Time:      {duration_dec:.4f} seconds")
    print(f"    Avg Latency:     {(duration_dec/iterations)*1e3:.3f} ms/message")
    print(f"    Throughput:      {throughput_dec:.2f} KB/s\n")

    # --- 3. MEMORY USAGE ---
    print("[3] Memory Consumption")
    tracemalloc.start()
    _ = ascon_encrypt(key, nonce, ad, plaintext, variant=variant)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(f"    Peak RAM usage:   {peak / 1024:.2f} KB\n")

    # --- 4. SECURITY (AVALANCHE EFFECT) ---
    print("[4] Security: Avalanche Effect (first 64 bits of ciphertext)")
    pt2 = bytearray(plaintext)
    pt2[0] ^= 1  # flip 1 bit
    ct2 = ascon_encrypt(key, nonce, ad, bytes(pt2), variant=variant)

    # Compare first 8 bytes of ciphertext (excluding tag)
    c1 = ct_and_tag[:8]
    c2 = ct2[:8]
    diff = bin(int.from_bytes(c1, "big") ^ int.from_bytes(c2, "big")).count("1")
    avalanche = (diff / 64) * 100
    print(f"    Bits changed:     {diff} / 64")
    print(f"    Avalanche %:      {avalanche:.2f}% (Ideal ~50%)")
    print("==============================================")


if __name__ == "__main__":
    run_evaluation()