#!/usr/bin/env python3
import time
import tracemalloc
import os
import sys

# === ASCON CORE LOGIC ===

def rotr(val, r):
    return ((val & 0xFFFFFFFFFFFFFFFF) >> r) | ((val << (64 - r)) & 0xFFFFFFFFFFFFFFFF)

def bytes_to_int(b):
    return int.from_bytes(b, "big")

def int_to_bytes(integer, nbytes):
    return integer.to_bytes(nbytes, "big")

def bytes_to_state(b):
    return [bytes_to_int(b[8*w:8*(w+1)]) for w in range(5)]

def ascon_permutation(S, rounds=1):
    constants = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
    for r in range(12-rounds, 12):
        S[2] ^= constants[r]
        S[0] ^= S[4]; S[4] ^= S[3]; S[2] ^= S[1]
        T = [(~S[i] & 0xFFFFFFFFFFFFFFFF) & S[(i+1)%5] for i in range(5)]
        for i in range(5): S[i] ^= T[(i+1)%5]
        S[1] ^= S[0]; S[0] ^= S[4]; S[3] ^= S[2]; S[2] ^= 0xFFFFFFFFFFFFFFFF
        S[0] ^= rotr(S[0], 19) ^ rotr(S[0], 28)
        S[1] ^= rotr(S[1], 61) ^ rotr(S[1], 39)
        S[2] ^= rotr(S[2], 1)  ^ rotr(S[2], 6)
        S[3] ^= rotr(S[3], 10) ^ rotr(S[3], 17)
        S[4] ^= rotr(S[4], 7)  ^ rotr(S[4], 41)

def ascon_initialize(S, k, rate, a, b, key, nonce):
    iv = bytes([k, rate * 8, a, b] + (20-len(key))*[0]) + key + nonce
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(iv)
    ascon_permutation(S, a)
    zero_key = bytes_to_state((40-len(key))*b"\x00" + key)
    for i in range(5): S[i] ^= zero_key[i]

def ascon_process_associated_data(S, b, rate, ad):
    if len(ad) > 0:
        a_padding = b"\x80" + b"\x00" * (rate - (len(ad) % rate) - 1)
        a_padded = ad + a_padding
        for block in range(0, len(a_padded), rate):
            S[0] ^= bytes_to_int(a_padded[block:block+8])
            if rate == 16: S[1] ^= bytes_to_int(a_padded[block+8:block+16])
            ascon_permutation(S, b)
    S[4] ^= 1

def ascon_process_plaintext(S, b, rate, plaintext):
    p_lastlen = len(plaintext) % rate
    p_padding = b"\x80" + b"\x00" * (rate - p_lastlen - 1)
    p_padded = plaintext + p_padding
    ciphertext = b""
    for block in range(0, len(p_padded) - rate, rate):
        if rate == 8:
            S[0] ^= bytes_to_int(p_padded[block:block+8])
            ciphertext += int_to_bytes(S[0], 8)
        elif rate == 16:
            S[0] ^= bytes_to_int(p_padded[block:block+8])
            S[1] ^= bytes_to_int(p_padded[block+8:block+16])
            ciphertext += int_to_bytes(S[0], 8) + int_to_bytes(S[1], 8)
        ascon_permutation(S, b)
    last_block = p_padded[-rate:]
    S[0] ^= bytes_to_int(last_block[:8])
    if rate == 16: S[1] ^= bytes_to_int(last_block[8:])
    res = int_to_bytes(S[0], 8)
    if rate == 16: res += int_to_bytes(S[1], 8)
    ciphertext += res[:p_lastlen]
    return ciphertext

def ascon_process_ciphertext(S, b, rate, ciphertext):
    c_lastlen = len(ciphertext) % rate
    plaintext = b""
    for block in range(0, len(ciphertext) - c_lastlen, rate):
        if rate == 8:
            Ci = bytes_to_int(ciphertext[block:block+8])
            plaintext += int_to_bytes(S[0] ^ Ci, 8)
            S[0] = Ci
        elif rate == 16:
            Ci0 = bytes_to_int(ciphertext[block:block+8])
            Ci1 = bytes_to_int(ciphertext[block+8:block+16])
            plaintext += int_to_bytes(S[0] ^ Ci0, 8) + int_to_bytes(S[1] ^ Ci1, 8)
            S[0], S[1] = Ci0, Ci1
        ascon_permutation(S, b)
    last_c = ciphertext[-(c_lastlen):] if c_lastlen > 0 else b""
    s_bytes = int_to_bytes(S[0], 8) + (int_to_bytes(S[1], 8) if rate == 16 else b"")
    last_p = bytes(c ^ s for c, s in zip(last_c, s_bytes[:c_lastlen]))
    plaintext += last_p
    padded = last_p + b"\x80" + b"\x00" * (rate - c_lastlen - 1)
    S[0] ^= bytes_to_int(padded[:8])
    if rate == 16: S[1] ^= bytes_to_int(padded[8:])
    return plaintext

def ascon_finalize(S, rate, a, key):
    S[rate//8+0] ^= bytes_to_int(key[0:8])
    S[rate//8+1] ^= bytes_to_int(key[8:16])
    if len(key) == 20: S[rate//8+2] ^= bytes_to_int(key[16:] + b"\x00"*4)
    ascon_permutation(S, a)
    S[3] ^= bytes_to_int(key[-16:-8])
    S[4] ^= bytes_to_int(key[-8:])
    return int_to_bytes(S[3], 8) + int_to_bytes(S[4], 8)

# === WRAPPERS ===

def ascon_encrypt(key, nonce, ad, plaintext, variant="Ascon-128"):
    k, a, b = (160, 12, 12) if variant == "Ascon-80pq" else (128, 12, 6 if variant == "Ascon-128" else 8)
    rate = 16 if variant == "Ascon-128a" else 8
    S = [0]*5
    ascon_initialize(S, k, rate, a, b, key, nonce)
    ascon_process_associated_data(S, b, rate, ad)
    ct = ascon_process_plaintext(S, b, rate, plaintext)
    tag = ascon_finalize(S, rate, a, key)
    return ct + tag

def ascon_decrypt(key, nonce, ad, ct_and_tag, variant="Ascon-128"):
    if len(ct_and_tag) < 16: return None
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    k, a, b = (160, 12, 12) if variant == "Ascon-80pq" else (128, 12, 6 if variant == "Ascon-128" else 8)
    rate = 16 if variant == "Ascon-128a" else 8
    S = [0]*5
    ascon_initialize(S, k, rate, a, b, key, nonce)
    ascon_process_associated_data(S, b, rate, ad)
    pt = ascon_process_ciphertext(S, b, rate, ct)
    expected_tag = ascon_finalize(S, rate, a, key)
    return pt if expected_tag == tag else None

# === AUTOMATED TEST LOOP ===

def run_automated_test_loop():
    variants = ["Ascon-128", "Ascon-128a", "Ascon-80pq"]
    test_sizes = [0, 1, 7, 8, 9, 15, 16, 17, 32, 128] # Testing different block boundaries
    
    print("\n" + "="*80)
    print(f"{'ASCON AUTOMATED STRESS TEST LOOP':^80}")
    print("="*80)
    print(f"{'Variant':<15} | {'Size':<6} | {'Enc/Dec':<8} | {'Integrity':<10} | {'Throughput':<15}")
    print("-" * 80)

    for v in variants:
        keysize = 20 if v == "Ascon-80pq" else 16
        key = os.urandom(keysize)
        nonce = os.urandom(16)
        ad = b"header_info"

        for size in test_sizes:
            plaintext = os.urandom(size)
            
            # 1. Performance Measurement
            start = time.perf_counter()
            ct = ascon_encrypt(key, nonce, ad, plaintext, v)
            duration = time.perf_counter() - start
            
            # 2. Correctness Check
            pt = ascon_decrypt(key, nonce, ad, ct, v)
            correct = "PASS" if pt == plaintext else "FAIL"

            # 3. Integrity Check (Tampering)
            tampered_ct = bytearray(ct)
            if len(tampered_ct) > 16:
                tampered_ct[0] ^= 1 # Corrupt ciphertext
            else:
                tampered_ct[-1] ^= 1 # Corrupt tag
            
            tampered_res = ascon_decrypt(key, nonce, ad, bytes(tampered_ct), v)
            integrity = "SECURE" if tampered_res is None else "VULN"

            # 4. Throughput Calculation
            throughput = (size / 1024) / duration if duration > 0 else 0
            
            print(f"{v:<15} | {size:>4} B  | {correct:<8} | {integrity:<10} | {throughput:>10.2f} KB/s")
    
    print("="*80)
    print("TEST LOOP COMPLETE.\n")

if __name__ == "__main__":
    run_automated_test_loop()