import time
import tracemalloc
import os
import struct

class Ascon128:
   

    def __init__(self):
        # Ascon-AEAD128 parameters
        self.IV = 0x80400c0600000000
        self.MASK = 0xFFFFFFFFFFFFFFFF
        self.RATE = 8            # bytes
        self.A = 12              # init/final rounds
        self.B = 6               # intermediate rounds
        self.TAGLEN = 16         # bytes

    # ---------- helpers ----------
    def _rotate_right(self, val, n):
        return ((val >> n) | (val << (64 - n))) & self.MASK

    def _load64(self, b8: bytes) -> int:
        return int.from_bytes(b8, "big")

    def _store64(self, x: int) -> bytes:
        return (x & self.MASK).to_bytes(8, "big")

    def _pad10star1(self, m: bytes, rate: int) -> bytes:
        padlen = (-len(m) - 1) % rate
        return m + b"\x80" + b"\x00" * padlen

    # ---------- permutation ----------
    def _ascon_permutation(self, state, rounds):
        """ The p permutation core: 12 rounds for init/final, 6 for intermediate. """
        constants = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]

        for i in range(12 - rounds, 12):
            # 1. Addition of Round Constant
            state[2] ^= constants[i]

            # 2. Substitution Layer (S-Box)
            state[0] ^= state[4]
            state[4] ^= state[3]
            state[2] ^= state[1]
            t = [(~s & self.MASK) for s in state]

            s0 = state[0] ^ (t[1] & state[2])
            s1 = state[1] ^ (t[2] & state[3])
            s2 = state[2] ^ (t[3] & state[4])
            s3 = state[3] ^ (t[4] & state[0])
            s4 = state[4] ^ (t[0] & state[1])

            s1 ^= s0
            s0 ^= s4
            s3 ^= s2
            s2 = (~s2) & self.MASK
            state = [s0, s1, s2, s3, s4]

            # 3. Linear Diffusion Layer
            state[0] ^= self._rotate_right(state[0], 19) ^ self._rotate_right(state[0], 28)
            state[1] ^= self._rotate_right(state[1], 61) ^ self._rotate_right(state[1], 39)
            state[2] ^= self._rotate_right(state[2], 1)  ^ self._rotate_right(state[2], 6)
            state[3] ^= self._rotate_right(state[3], 10) ^ self._rotate_right(state[3], 17)
            state[4] ^= self._rotate_right(state[4], 7)  ^ self._rotate_right(state[4], 41)

        return state

    # ---------- AEAD: init / absorb AD / encrypt / decrypt / finalize ----------
    def _init_state(self, key: int, nonce: int):
        # Split 128-bit key and nonce into 64-bit words
        k0, k1 = (key >> 64) & self.MASK, key & self.MASK
        n0, n1 = (nonce >> 64) & self.MASK, nonce & self.MASK

        state = [self.IV, k0, k1, n0, n1]
        state = self._ascon_permutation(state, self.A)
        state[3] ^= k0
        state[4] ^= k1
        return state, k0, k1

    def _absorb_ad(self, state, ad: bytes):
        if not ad:
            return state
        adp = self._pad10star1(ad, self.RATE)
        for i in range(0, len(adp), self.RATE):
            state[0] ^= self._load64(adp[i:i+self.RATE])
            state = self._ascon_permutation(state, self.B)
        return state

    def encrypt(self, key: int, nonce: int, plaintext: bytes, ad: bytes = b"") -> bytes:
        """
        Encrypt arbitrary-length plaintext with optional associated data (ad).
        Returns: ciphertext||tag  (tag is 16 bytes appended)
        """
        state, k0, k1 = self._init_state(key, nonce)

        # 1) AD
        state = self._absorb_ad(state, ad)

        # 2) domain separation
        state[4] ^= 1

        # 3) encrypt message
        ct = bytearray()
        if plaintext:
            full = len(plaintext) // self.RATE
            rem = len(plaintext) % self.RATE

            # full blocks
            for i in range(full):
                mblk = plaintext[i*self.RATE:(i+1)*self.RATE]
                state[0] ^= self._load64(mblk)
                ct += self._store64(state[0])
                state = self._ascon_permutation(state, self.B)

            # last block (including case rem==0 => last block is empty but we still absorb padding)
            last = plaintext[full*self.RATE:]
            padded = last + b"\x80" + b"\x00" * (self.RATE - len(last) - 1)
            state[0] ^= self._load64(padded)
            out = self._store64(state[0])
            ct += out[:len(last)]
        else:
            # absorb padding only for empty message
            state[0] ^= self._load64(b"\x80" + b"\x00" * (self.RATE - 1))

        # 4) finalize + tag
        state[1] ^= k0
        state[2] ^= k1
        state = self._ascon_permutation(state, self.A)
        state[3] ^= k0
        state[4] ^= k1
        tag = self._store64(state[3]) + self._store64(state[4])

        return bytes(ct) + tag

    def decrypt(self, key: int, nonce: int, ciphertext_and_tag: bytes, ad: bytes = b"") -> bytes | None:
        """
        Decrypt ciphertext||tag with optional associated data (ad).
        Returns plaintext bytes if authentication succeeds, else None.
        """
        if len(ciphertext_and_tag) < self.TAGLEN:
            return None
        ct = ciphertext_and_tag[:-self.TAGLEN]
        tag = ciphertext_and_tag[-self.TAGLEN:]

        state, k0, k1 = self._init_state(key, nonce)

        # 1) AD
        state = self._absorb_ad(state, ad)

        # 2) domain separation
        state[4] ^= 1

        # 3) decrypt message
        pt = bytearray()
        if ct:
            full = len(ct) // self.RATE
            rem = len(ct) % self.RATE

            # full blocks
            for i in range(full):
                cblk = ct[i*self.RATE:(i+1)*self.RATE]
                cword = self._load64(cblk)
                mword = state[0] ^ cword
                pt += self._store64(mword)
                state[0] = cword
                state = self._ascon_permutation(state, self.B)

            # last block
            lastc = ct[full*self.RATE:]
            if rem != 0:
                s0_bytes = self._store64(state[0])
                lastm = bytes(x ^ y for x, y in zip(lastc, s0_bytes[:rem]))
                pt += lastm
                padded = lastm + b"\x80" + b"\x00" * (self.RATE - rem - 1)
                state[0] ^= self._load64(padded)
            else:
                # exact multiple: absorb padding only
                state[0] ^= self._load64(b"\x80" + b"\x00" * (self.RATE - 1))
        else:
            # empty message: absorb padding only
            state[0] ^= self._load64(b"\x80" + b"\x00" * (self.RATE - 1))

        # 4) finalize + verify tag
        state[1] ^= k0
        state[2] ^= k1
        state = self._ascon_permutation(state, self.A)
        state[3] ^= k0
        state[4] ^= k1
        comp = self._store64(state[3]) + self._store64(state[4])

        diff = 0
        for a, b in zip(comp, tag):
            diff |= a ^ b
        if diff != 0:
            return None
        return bytes(pt)


# --- PERFORMANCE EVALUATION SUITE ---

def run_evaluation():
    print("==============================================")
    print("   ASCON-AEAD128 (RATE=8) EVALUATION REPORT   ")
    print("==============================================\n")

    ascon = Ascon128()

    # Standard test inputs (int key/nonce to match your original style)
    key = 0x000102030405060708090A0B0C0D0E0F
    nonce = 0x000102030405060708090A0B0C0D0E0F

    # Plaintext now bytes (arbitrary length)
    plaintext = b"HelloIoT - multi-block test payload (Ascon AEAD1281)!"
    ad = b"hdr:device=10203040;ctr=1"  # associated data (authenticated, not encrypted)

    # --- 1. VALIDATION (ENCRYPTION & DECRYPTION) ---
    print("[1] Validation Check (Encrypt/Decrypt + Tag Verify + AD binding)")
    ct_and_tag = ascon.encrypt(key, nonce, plaintext, ad=ad)
    decrypted = ascon.decrypt(key, nonce, ct_and_tag, ad=ad)

    print(f"    Plaintext:     {plaintext!r}")
    print(f"    AD (hex):      {ad.hex()}")
    print(f"    CT||TAG (hex): {ct_and_tag.hex()}")
    print(f"    Decrypted:     {decrypted!r}")
    print(f"    Status:        {'SUCCESS' if decrypted == plaintext else 'FAIL'}\n")

    # Tamper test (flip a bit)
    tampered = bytearray(ct_and_tag)
    tampered[0] ^= 1
    tampered_out = ascon.decrypt(key, nonce, bytes(tampered), ad=ad)
    print("    Tamper test:   ", "PASS (rejected)" if tampered_out is None else "FAIL (accepted)")

    # AD binding test
    bad_ad = ad + b"x"
    bad_ad_out = ascon.decrypt(key, nonce, ct_and_tag, ad=bad_ad)
    print("    AD binding:    ", "PASS (rejected)" if bad_ad_out is None else "FAIL (accepted)")
    print()

    # --- 2. EXECUTION TIME & THROUGHPUT (ENCRYPTION) ---
    print("[2] Throughput & Timing (Encryption)")
    iterations = 2000  # lower than 20000 because multi-block + Python is slower
    start_time = time.perf_counter()
    for _ in range(iterations):
        ascon.encrypt(key, nonce, plaintext, ad=ad)
    end_time = time.perf_counter()
    duration = end_time - start_time

    total_bytes = iterations * len(plaintext)
    kb_processed = total_bytes / 1024
    throughput = kb_processed / duration

    print(f"    Messages:        {iterations}")
    print(f"    Payload bytes:   {len(plaintext)}")
    print(f"    Total Time:      {duration:.4f} seconds")
    print(f"    Avg Latency:     {(duration/iterations)*1e3:.3f} ms/message")
    print(f"    Throughput:      {throughput:.2f} KB/s\n")

    # --- 2b. DECRYPTION TIMING ---
    print("[2b] Throughput & Timing (Decryption + Tag Verify)")
    start_time = time.perf_counter()
    for _ in range(iterations):
        out = ascon.decrypt(key, nonce, ct_and_tag, ad=ad)
        if out is None:
            raise RuntimeError("Unexpected auth failure in timing test")
    end_time = time.perf_counter()
    duration_dec = end_time - start_time

    throughput_dec = kb_processed / duration_dec
    print(f"    Messages:        {iterations}")
    print(f"    Total Time:      {duration_dec:.4f} seconds")
    print(f"    Avg Latency:     {(duration_dec/iterations)*1e3:.3f} ms/message")
    print(f"    Throughput:      {throughput_dec:.2f} KB/s\n")

    # --- 3. MEMORY USAGE ---
    print("[3] Memory Consumption")
    tracemalloc.start()
    _ = ascon.encrypt(key, nonce, plaintext, ad=ad)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(f"    Peak RAM usage:   {peak / 1024:.2f} KB\n")

    # --- 4. SECURITY (AVALANCHE EFFECT) ---
    # Avalanche effect is best shown on a fixed-size block, but we'll do it on first 8 bytes of ciphertext.
    print("[4] Security: Avalanche Effect (first 64 bits of ciphertext)")
    pt2 = bytearray(plaintext)
    pt2[0] ^= 1  # flip 1 bit
    ct2 = ascon.encrypt(key, nonce, bytes(pt2), ad=ad)

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