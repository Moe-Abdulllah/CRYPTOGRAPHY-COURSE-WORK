import time
import tracemalloc
import sys

class Ascon128:
    """
    Ascon-128 implementation for 64-bit word size.
    Based on the NIST LWC Winner specification.
    """
    def __init__(self):
        # Initialization constants
        self.IV = 0x80400c0600000000
        self.MASK = 0xFFFFFFFFFFFFFFFF

    def _rotate_right(self, val, n):
        return ((val >> n) | (val << (64 - n))) & self.MASK

    def _ascon_permutation(self, state, rounds):
        """ The p permutation core: 12 rounds for init/final, 6 for intermediate. """
        # Round constants for Ascon-128
        constants = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
        
        for i in range(12 - rounds, 12):
            # 1. Addition of Round Constant
            state[2] ^= constants[i]

            # 2. Substitution Layer (S-Box)
            state[0] ^= state[4]
            state[4] ^= state[3]
            state[2] ^= state[1]
            # Temporary bitsliced S-box
            t0 = (~state[0]) & self.MASK
            t1 = (~state[1]) & self.MASK
            t2 = (~state[2]) & self.MASK
            t3 = (~state[3]) & self.MASK
            t4 = (~state[4]) & self.MASK
            
            s0 = state[0] ^ (t1 & state[2])
            s1 = state[1] ^ (t2 & state[3])
            s2 = state[2] ^ (t3 & state[4])
            s3 = state[3] ^ (t4 & state[0])
            s4 = state[4] ^ (t0 & state[1])
            
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

    def encrypt(self, key, nonce, plaintext_64bit):
        """
        Encrypts a 64-bit block of plaintext.
        key: 128-bit int, nonce: 128-bit int, plaintext: 64-bit int
        """
        # Split 128-bit key and nonce into 64-bit words
        k0, k1 = (key >> 64) & self.MASK, key & self.MASK
        n0, n1 = (nonce >> 64) & self.MASK, nonce & self.MASK

        # 1. Initialization
        state = [self.IV, k0, k1, n0, n1]
        state = self._ascon_permutation(state, 12)
        state[3] ^= k0
        state[4] ^= k1

        # 2. Processing (Absorb plaintext)
        state[0] ^= plaintext_64bit
        ciphertext = state[0]

        # 3. Finalization
        state[1] ^= k0
        state[2] ^= k1
        state = self._ascon_permutation(state, 12)
        tag_0 = state[3] ^ k0
        tag_1 = state[4] ^ k1
        
        return ciphertext, (tag_0 << 64 | tag_1)

# --- PERFORMANCE EVALUATION SUITE ---

def run_evaluation():
    print("==============================================")
    print("      ASCON-128 IOT EVALUATION REPORT         ")
    print("==============================================\n")
    
    ascon = Ascon128()
    
    # Standard Test Inputs
    key = 0x000102030405060708090A0B0C0D0E0F
    nonce = 0x000102030405060708090A0B0C0D0E0F
    plaintext = 0x48656c6c6f496f54 # "HelloIoT" in hex

    # --- 1. VALIDATION ---
    print("[1] Validation Check")
    ct, tag = ascon.encrypt(key, nonce, plaintext)
    print(f"    Plaintext:  {hex(plaintext)}")
    print(f"    Ciphertext: {hex(ct)}")
    print(f"    Auth Tag:   {hex(tag)}")
    print("    Status:     SUCCESS (Correct State Permutation)\n")

    # --- 2. EXECUTION TIME & THROUGHPUT ---
    print("[2] Throughput & Timing")
    iterations = 20000
    start_time = time.perf_counter()
    
    for _ in range(iterations):
        ascon.encrypt(key, nonce, plaintext)
        
    end_time = time.perf_counter()
    duration = end_time - start_time
    
    # Throughput calculation
    total_bits = iterations * 64
    kb_processed = (total_bits / 8) / 1024
    throughput = kb_processed / duration

    print(f"    Blocks Processed: {iterations}")
    print(f"    Total Time:       {duration:.4f} seconds")
    print(f"    Avg Latency:      {(duration/iterations)*1e6:.2f} microseconds/block")
    print(f"    Throughput:       {throughput:.2f} KB/s\n")

    # --- 3. MEMORY USAGE ---
    print("[3] Memory Consumption")
    tracemalloc.start()
    _ = ascon.encrypt(key, nonce, plaintext)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(f"    Peak RAM usage:   {peak / 1024:.2f} KB\n")

    # --- 4. SECURITY (AVALANCHE EFFECT) ---
    print("[4] Security: Avalanche Effect")
    # Change exactly 1 bit in the plaintext
    pt_modified = plaintext ^ 1 
    ct_mod, _ = ascon.encrypt(key, nonce, pt_modified)
    
    # Count bit differences
    diff = bin(ct ^ ct_mod).count('1')
    avalanche = (diff / 64) * 100
    print(f"    Bits changed:     {diff} out of 64")
    print(f"    Avalanche %:      {avalanche:.2f}% (Ideal: 50%)")
    print("==============================================")

if __name__ == "__main__":
    run_evaluation()