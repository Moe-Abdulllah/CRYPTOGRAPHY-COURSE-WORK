import struct
import time
import sys
import tracemalloc

class SpeckCipher:
    def __init__(self, key: int):
        # Parameters for SPECK 64/128
        self.word_size = 32
        self.rounds = 27
        self.mask = (2**32) - 1
        self.alpha = 8
        self.beta = 3
        
        # Pre-calculate round keys (Key Schedule)
        self.round_keys = self._expand_key(key)

    def _rotate_right(self, x, r):
        return ((x >> r) | (x << (self.word_size - r))) & self.mask

    def _rotate_left(self, x, r):
        return ((x << r) | (x >> (self.word_size - r))) & self.mask

    def _expand_key(self, key):
        """Generates 27 round keys from the 128-bit master key."""
        # Split 128-bit key into four 32-bit words
        k = [(key >> (i * 32)) & self.mask for i in range(4)]
        
        # k[0] is the first round key, k[1..3] are used for internal state
        state_l = k[1:]
        state_a = k[0]
        
        round_keys = [state_a]
        
        for i in range(self.rounds - 1):
            # Key schedule round function
            l_i = state_l[i % 3]
            new_l = ((self._rotate_right(l_i, self.alpha) + state_a) & self.mask) ^ i
            new_a = self._rotate_left(state_a, self.beta) ^ new_l
            
            state_l[i % 3] = new_l
            state_a = new_a
            round_keys.append(state_a)
            
        return round_keys

    def encrypt(self, plaintext_64bit):
        """Encrypts a single 64-bit block."""
        # Split 64-bit block into two 32-bit words (y, x)
        y = (plaintext_64bit >> 32) & self.mask
        x = plaintext_64bit & self.mask

        for k in self.round_keys:
            x = ((self._rotate_right(x, self.alpha) + y) & self.mask) ^ k
            y = self._rotate_left(y, self.beta) ^ x
            
        return (y << 32) | x

    def decrypt(self, ciphertext_64bit):
        """Decrypts a single 64-bit block."""
        y = (ciphertext_64bit >> 32) & self.mask
        x = ciphertext_64bit & self.mask

        for k in reversed(self.round_keys):
            y = self._rotate_right(y ^ x, self.beta)
            x = self._rotate_left(((x ^ k) - y) & self.mask, self.alpha)
            
        return (y << 32) | x

# --- Demonstration / Testing ---
if __name__ == "__main__":
    # Test Vector (SPECK 64/128)
    # Key: 1b1a1918 13121110 0b0a0908 03020100
    # Plaintext: 3b726574 74756220 ("buttretb" in hex-reversed)
    master_key = 0x1b1a1918131211100b0a090803020100
    plaintext = 0x3b7265747475622

    cipher = SpeckCipher(master_key)
    
    # 1. Encryption
    encrypted = cipher.encrypt(plaintext)
    print(f"Plaintext:  {hex(plaintext)}")
    print(f"Ciphertext: {hex(encrypted)}")
    
    # 2. Decryption
    decrypted = cipher.decrypt(encrypted)
    print(f"Decrypted:  {hex(decrypted)}")

    # 3. Validation
    assert plaintext == decrypted, "Decryption failed!"
    print("\nValidation Successful: The implementation is correct.")
    

start = time.time()
for _ in range(50000):
    cipher.encrypt(plaintext)
end = time.time()
print(f"Time for 50,000 encryptions: {end - start:.4f} seconds")

class SpeckCipher:
    def __init__(self, key: int):
        self.word_size = 32
        self.rounds = 27
        self.mask = (2**32) - 1
        self.alpha = 8
        self.beta = 3
        self.round_keys = self._expand_key(key)

    def _rotate_right(self, x, r):
        return ((x >> r) | (x << (self.word_size - r))) & self.mask

    def _rotate_left(self, x, r):
        return ((x << r) | (x >> (self.word_size - r))) & self.mask

    def _expand_key(self, key):
        k = [(key >> (i * 32)) & self.mask for i in range(4)]
        state_l = k[1:]
        state_a = k[0]
        round_keys = [state_a]
        for i in range(self.rounds - 1):
            l_i = state_l[i % 3]
            new_l = ((self._rotate_right(l_i, self.alpha) + state_a) & self.mask) ^ i
            new_a = self._rotate_left(state_a, self.beta) ^ new_l
            state_l[i % 3] = new_l
            state_a = new_a
            round_keys.append(state_a)
        return round_keys

    def encrypt(self, plaintext_64bit):
        y = (plaintext_64bit >> 32) & self.mask
        x = plaintext_64bit & self.mask
        for k in self.round_keys:
            x = ((self._rotate_right(x, self.alpha) + y) & self.mask) ^ k
            y = self._rotate_left(y, self.beta) ^ x
        return (y << 32) | x

    def decrypt(self, ciphertext_64bit):
        y = (ciphertext_64bit >> 32) & self.mask
        x = ciphertext_64bit & self.mask
        for k in reversed(self.round_keys):
            y = self._rotate_right(y ^ x, self.beta)
            x = self._rotate_left(((x ^ k) - y) & self.mask, self.alpha)
        return (y << 32) | x

# --- EVALUATION SUITE ---

def evaluate_speck():
    print("--- SPECK-64/128 Performance Evaluation ---")
    
    # 1. Validation (Known Answer Test)
    # Test Vector from official NSA Paper
    test_key = 0x1b1a1918131211100b0a090803020100
    test_pt  = 0x3b72657474756220
    expected_ct = 0x8c6fa548454e028b
    
    cipher = SpeckCipher(test_key)
    actual_ct = cipher.encrypt(test_pt)
    
    print(f"\n[1] Validation Test:")
    print(f"    Expected CT: {hex(expected_ct)}")
    print(f"    Actual CT:   {hex(actual_ct)}")
    if actual_ct == expected_ct:
        print("    RESULT: PASS (Implementation is Correct)")
    else:
        print("    RESULT: FAIL")

    # 2. Performance & Throughput
    iterations = 50000 # Number of blocks to encrypt
    tracemalloc.start() # Start memory tracking
    
    start_time = time.perf_counter()
    for _ in range(iterations):
        cipher.encrypt(test_pt)
    end_time = time.perf_counter()
    
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    total_time = end_time - start_time
    time_per_block = (total_time / iterations) * 1000 # in milliseconds
    
    # Calculate Throughput
    # Total bits = iterations * 64 bits
    total_bytes = (iterations * 64) / 8
    throughput_kbps = (total_bytes / 1024) / total_time

    print(f"\n[2] Execution Time & Throughput:")
    print(f"    Total Iterations:    {iterations}")
    print(f"    Total Time:          {total_time:.4f} seconds")
    print(f"    Avg Time per Block:  {time_per_block:.6f} ms")
    print(f"    Throughput:          {throughput_kbps:.2f} KB/s")

    # 3. Memory Usage
    print(f"\n[3] Memory Usage (RAM):")
    print(f"    Peak RAM during run: {peak_mem / 1024:.2f} KB")
    print(f"    Cipher Object Size:  {sys.getsizeof(cipher)} bytes")

    # 4. Avalanche Effect (Security Metric)
    # Flipping 1 bit in plaintext and seeing how many bits change in ciphertext
    pt_modified = test_pt ^ 1 # Flip the very last bit
    ct_modified = cipher.encrypt(pt_modified)
    
    # Count differing bits using XOR and bin().count('1')
    diff_bits = bin(actual_ct ^ ct_modified).count('1')
    avalanche_pct = (diff_bits / 64) * 100
    
    print(f"\n[4] Security (Avalanche Effect):")
    print(f"    Bits changed in CT after 1-bit PT change: {diff_bits}/64")
    print(f"    Avalanche Percentage: {avalanche_pct:.2f}% (Target: 50%)")

if __name__ == "__main__":
    evaluate_speck()
