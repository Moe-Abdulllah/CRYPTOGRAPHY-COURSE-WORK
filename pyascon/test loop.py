import time
import tracemalloc
import os
import struct

class Ascon128:
    def __init__(self):
        self.IV = 0x80400c0600000000
        self.MASK = 0xFFFFFFFFFFFFFFFF
        self.RATE = 8            
        self.A = 12              
        self.B = 6               
        self.TAGLEN = 16         

    def _rotate_right(self, val, n):
        return ((val >> n) | (val << (64 - n))) & self.MASK

    def _load64(self, b8: bytes) -> int:
        return int.from_bytes(b8, "big")

    def _store64(self, x: int) -> bytes:
        return (x & self.MASK).to_bytes(8, "big")

    def _pad10star1(self, m: bytes, rate: int) -> bytes:
        padlen = (-len(m) - 1) % rate
        return m + b"\x80" + b"\x00" * padlen

    def _ascon_permutation(self, state, rounds):
        constants = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
        for i in range(12 - rounds, 12):
            state[2] ^= constants[i]
            state[0] ^= state[4]; state[4] ^= state[3]; state[2] ^= state[1]
            t = [(~s & self.MASK) for s in state]
            s0 = state[0] ^ (t[1] & state[2]); s1 = state[1] ^ (t[2] & state[3])
            s2 = state[2] ^ (t[3] & state[4]); s3 = state[3] ^ (t[4] & state[0])
            s4 = state[4] ^ (t[0] & state[1])
            s1 ^= s0; s0 ^= s4; s3 ^= s2; s2 = (~s2) & self.MASK
            state = [s0, s1, s2, s3, s4]
            state[0] ^= self._rotate_right(state[0], 19) ^ self._rotate_right(state[0], 28)
            state[1] ^= self._rotate_right(state[1], 61) ^ self._rotate_right(state[1], 39)
            state[2] ^= self._rotate_right(state[2], 1)  ^ self._rotate_right(state[2], 6)
            state[3] ^= self._rotate_right(state[3], 10) ^ self._rotate_right(state[3], 17)
            state[4] ^= self._rotate_right(state[4], 7)  ^ self._rotate_right(state[4], 41)
        return state

    def _init_state(self, key: int, nonce: int):
        k0, k1 = (key >> 64) & self.MASK, key & self.MASK
        n0, n1 = (nonce >> 64) & self.MASK, nonce & self.MASK
        state = [self.IV, k0, k1, n0, n1]
        state = self._ascon_permutation(state, self.A)
        state[3] ^= k0; state[4] ^= k1
        return state, k0, k1

    def _absorb_ad(self, state, ad: bytes):
        if not ad: return state
        adp = self._pad10star1(ad, self.RATE)
        for i in range(0, len(adp), self.RATE):
            state[0] ^= self._load64(adp[i:i+self.RATE])
            state = self._ascon_permutation(state, self.B)
        return state

    def encrypt(self, key: int, nonce: int, plaintext: bytes, ad: bytes = b"") -> bytes:
        state, k0, k1 = self._init_state(key, nonce)
        state = self._absorb_ad(state, ad)
        state[4] ^= 1
        ct = bytearray()
        if plaintext:
            full = len(plaintext) // self.RATE
            for i in range(full):
                mblk = plaintext[i*self.RATE:(i+1)*self.RATE]
                state[0] ^= self._load64(mblk)
                ct += self._store64(state[0])
                state = self._ascon_permutation(state, self.B)
            last = plaintext[full*self.RATE:]
            padded = last + b"\x80" + b"\x00" * (self.RATE - len(last) - 1)
            state[0] ^= self._load64(padded)
            out = self._store64(state[0])
            ct += out[:len(last)]
        else:
            state[0] ^= self._load64(b"\x80" + b"\x00" * (self.RATE - 1))
        state[1] ^= k0; state[2] ^= k1
        state = self._ascon_permutation(state, self.A)
        state[3] ^= k0; state[4] ^= k1
        tag = self._store64(state[3]) + self._store64(state[4])
        return bytes(ct) + tag

    def decrypt(self, key: int, nonce: int, ciphertext_and_tag: bytes, ad: bytes = b"") -> bytes | None:
        if len(ciphertext_and_tag) < self.TAGLEN: return None
        ct = ciphertext_and_tag[:-self.TAGLEN]
        tag = ciphertext_and_tag[-self.TAGLEN:]
        state, k0, k1 = self._init_state(key, nonce)
        state = self._absorb_ad(state, ad)
        state[4] ^= 1
        pt = bytearray()
        if ct:
            full = len(ct) // self.RATE
            for i in range(full):
                cblk = ct[i*self.RATE:(i+1)*self.RATE]
                cword = self._load64(cblk)
                mword = state[0] ^ cword
                pt += self._store64(mword)
                state[0] = cword
                state = self._ascon_permutation(state, self.B)
            lastc = ct[full*self.RATE:]
            rem = len(ct) % self.RATE
            if rem != 0:
                s0_bytes = self._store64(state[0])
                lastm = bytes(x ^ y for x, y in zip(lastc, s0_bytes[:rem]))
                pt += lastm
                padded = lastm + b"\x80" + b"\x00" * (self.RATE - rem - 1)
                state[0] ^= self._load64(padded)
            else:
                state[0] ^= self._load64(b"\x80" + b"\x00" * (self.RATE - 1))
        else:
            state[0] ^= self._load64(b"\x80" + b"\x00" * (self.RATE - 1))
        state[1] ^= k0; state[2] ^= k1
        state = self._ascon_permutation(state, self.A)
        state[3] ^= k0; state[4] ^= k1
        comp = self._store64(state[3]) + self._store64(state[4])
        diff = 0
        for a, b in zip(comp, tag): diff |= a ^ b
        return bytes(pt) if diff == 0 else None

# --- AUTOMATED TEST LOOP & PERFORMANCE EVALUATION ---

def run_automated_evaluation():
    ascon = Ascon128()
    key = 0x000102030405060708090A0B0C0D0E0F
    nonce = 0x000102030405060708090A0B0C0D0E0F
    
    # Payload sizes to test (in bytes)
    test_sizes = [0, 8, 16, 32, 64, 128, 256, 512, 1024]
    results = []

    print("==========================================================")
    print("   ASCON-128 AUTOMATED PERFORMANCE & VALIDATION LOOP      ")
    print("==========================================================\n")
    print(f"{'Size (B)':<10} | {'Status':<10} | {'Time (ms)':<12} | {'Throughput (KB/s)':<15}")
    print("-" * 60)

    for size in test_sizes:
        plaintext = b"A" * size
        ad = b"header"
        
        # 1. Correctness Check
        ct_tag = ascon.encrypt(key, nonce, plaintext, ad)
        decrypted = ascon.decrypt(key, nonce, ct_tag, ad)
        status = "PASS" if decrypted == plaintext else "FAIL"

        # 2. Performance Timing (Iterate to get stable average)
        iters = 500
        start = time.perf_counter()
        for _ in range(iters):
            ascon.encrypt(key, nonce, plaintext, ad)
        end = time.perf_counter()
        
        avg_time_ms = ((end - start) / iters) * 1000
        throughput = (size * iters / 1024) / (end - start) if (end-start) > 0 else 0

        print(f"{size:<10} | {status:<10} | {avg_time_ms:<12.4f} | {throughput:<15.2f}")
        results.append((size, avg_time_ms, throughput))

    # 3. Security Validation (Tamper Test)
    print("\n[Security Validation]")
    test_pt = b"Critical IoT Data"
    ct_tag = ascon.encrypt(key, nonce, test_pt)
    tampered = bytearray(ct_tag)
    tampered[0] ^= 1 # Flip one bit
    reject = ascon.decrypt(key, nonce, bytes(tampered))
    print(f"Tamper Detection: {'SUCCESS (Rejected)' if reject is None else 'FAILED'}")

    # 4. Memory Peak Usage
    tracemalloc.start()
    ascon.encrypt(key, nonce, b"A" * 1024)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(f"Peak RAM Usage:   {peak / 1024:.2f} KB")
    print("\n==========================================================")

if __name__ == "__main__":
    run_automated_evaluation()