class DES:
    # Initial permutation table
    IP = [58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6,
          64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7]

    # Final permutation table
    FP = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

    # Expansion table
    E = [32, 1, 2, 3, 4, 5,
         4, 5, 6, 7, 8, 9,
         8, 9, 10, 11, 12, 13,
         12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21,
         20, 21, 22, 23, 24, 25,
         24, 25, 26, 27, 28, 29,
         28, 29, 30, 31, 32, 1]

    # S-boxes
    S_BOXES = [
        # S1
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
        # S2
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
        # S3
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        # S4
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
        # S5
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
        # S6
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        # S7
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
        # S8
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
    ]

    # P-box permutation table
    P = [16, 7, 20, 21, 29, 12, 28, 17,
         1, 15, 23, 26, 5, 18, 31, 10,
         2, 8, 24, 14, 32, 27, 3, 9,
         19, 13, 30, 6, 22, 11, 4, 25]

    # PC-1 table (key schedule)
    PC1 = [57, 49, 41, 33, 25, 17, 9,
           1, 58, 50, 42, 34, 26, 18,
           10, 2, 59, 51, 43, 35, 27,
           19, 11, 3, 60, 52, 44, 36,
           63, 55, 47, 39, 31, 23, 15,
           7, 62, 54, 46, 38, 30, 22,
           14, 6, 61, 53, 45, 37, 29,
           21, 13, 5, 28, 20, 12, 4]

    # PC-2 table (key schedule)
    PC2 = [14, 17, 11, 24, 1, 5,
           3, 28, 15, 6, 21, 10,
           23, 19, 12, 4, 26, 8,
           16, 7, 27, 20, 13, 2,
           41, 52, 31, 37, 47, 55,
           30, 40, 51, 45, 33, 48,
           44, 49, 39, 56, 34, 53,
           46, 42, 50, 36, 29, 32]

    # Number of left shifts for each round
    SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    def __init__(self, key):
        """Initialize DES with a 64-bit key."""
        self.key = key
        self.round_keys = self._generate_round_keys()

    def _permute(self, block, table):
        """Permute the block according to the table."""
        return ''.join(block[i - 1] for i in table)

    def _left_shift(self, block, shifts):
        """Perform a circular left shift on the block."""
        return block[shifts:] + block[:shifts]

    def _xor(self, a, b):
        """Perform XOR operation on two binary strings."""
        return ''.join('1' if x != y else '0' for x, y in zip(a, b))

    def _string_to_binary(self, text):
        """Convert a string to binary."""
        return ''.join(format(ord(c), '08b') for c in text)

    def _binary_to_string(self, binary):
        """Convert binary to string."""
        return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))

    def _generate_round_keys(self):
        """Generate 16 48-bit round keys from the initial 64-bit key."""
        # Convert key to binary and apply PC-1
        key = self._string_to_binary(self.key)
        key = self._permute(key, self.PC1)
        
        # Split into left and right halves
        left = key[:28]
        right = key[28:]
        round_keys = []

        # Generate 16 round keys
        for i in range(16):
            # Perform left shifts
            left = self._left_shift(left, self.SHIFTS[i])
            right = self._left_shift(right, self.SHIFTS[i])
            
            # Combine and permute with PC-2
            combined = left + right
            round_key = self._permute(combined, self.PC2)
            round_keys.append(round_key)

        return round_keys

    def _f_function(self, right, round_key):
        """The Feistel (F) function."""
        # Expansion
        expanded = self._permute(right, self.E)
        
        # XOR with round key
        xored = self._xor(expanded, round_key)
        
        # S-box substitution
        output = ''
        for i in range(8):
            block = xored[i*6:(i+1)*6]
            row = int(block[0] + block[5], 2)
            col = int(block[1:5], 2)
            output += format(self.S_BOXES[i][row][col], '04b')
        
        # P-box permutation
        return self._permute(output, self.P)

    def encrypt(self, plaintext):
        """Encrypt a plaintext message."""
        # Convert to binary and apply initial permutation
        binary = self._string_to_binary(plaintext)
        block = self._permute(binary, self.IP)
        
        # Split into left and right halves
        left = block[:32]
        right = block[32:]
        
        # 16 rounds of Feistel network
        for i in range(16):
            new_right = self._xor(left, self._f_function(right, self.round_keys[i]))
            left = right
            right = new_right
        
        # Final permutation
        combined = right + left  # Note: reverse order for final combination
        ciphertext_binary = self._permute(combined, self.FP)
        return self._binary_to_string(ciphertext_binary)

    def decrypt(self, ciphertext):
        """Decrypt a ciphertext message."""
        # Decryption is the same as encryption but with reversed round keys
        temp = self.round_keys
        self.round_keys = self.round_keys[::-1]
        plaintext = self.encrypt(ciphertext)
        self.round_keys = temp
        return plaintext


    def encrypt_message(self, message):
        """Encrypt a message of any length (adds padding if needed)."""
        # Pad message to be multiple of 8 bytes
        padding_length = 8 - (len(message) % 8)
        padded_message = message + chr(padding_length) * padding_length
        
        # Encrypt each 8-byte block
        ciphertext = ''
        for i in range(0, len(padded_message), 8):
            block = padded_message[i:i+8]
            ciphertext += self.encrypt(block)
        return ciphertext

    def decrypt_message(self, ciphertext):
        """Decrypt a message and remove padding."""
        # Decrypt each 8-byte block
        plaintext = ''
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i+8]
            plaintext += self.decrypt(block)
        
        # Remove padding
        padding_length = ord(plaintext[-1])
        return plaintext[:-padding_length]

def print_binary(text):
    """Helper function to print binary representation of text."""
    binary = ''.join(format(ord(c), '08b') for c in text)
    return ' '.join(binary[i:i+8] for i in range(0, len(binary), 8))

def main():
    # Test key and message
    key = "Secret_K"  # 8-byte key
    message = "Hello, World! This is a test message."
    
    print("DES Encryption/Decryption Demonstration")
    print("-" * 50)
    
    # Create DES instance
    des = DES(key)
    
    # Print key information
    print(f"Key: {key}")
    print(f"Key in Binary: {print_binary(key)}")
    print("-" * 50)
    
    # Print original message
    print(f"Original Message: {message}")
    print(f"Original First Block in Binary: {print_binary(message[:8])}")
    print("-" * 50)
    
    # Perform encryption
    ciphertext = des.encrypt_message(message)
    print("Encrypted Message (hex):", ''.join(hex(ord(c))[2:].zfill(2) for c in ciphertext))
    print(f"First Block in Binary: {print_binary(ciphertext[:8])}")
    print("-" * 50)
    
    # Perform decryption
    decrypted = des.decrypt_message(ciphertext)
    print(f"Decrypted Message: {decrypted}")
    print(f"Decrypted First Block in Binary: {print_binary(decrypted[:8])}")
    print("-" * 50)
    
    # Demonstrate the avalanche effect
    print("Demonstrating Avalanche Effect:")
    slightly_different_message = "Hello. World! This is a test message."  # Changed comma to period
    different_ciphertext = des.encrypt_message(slightly_different_message)
    
    # Count bit differences in first block
    original_bits = ''.join(format(ord(c), '08b') for c in ciphertext[:8])
    modified_bits = ''.join(format(ord(c), '08b') for c in different_ciphertext[:8])
    differences = sum(1 for a, b in zip(original_bits, modified_bits) if a != b)
    
    print(f"Changed one character (comma to period)")
    print(f"Number of different bits in first block: {differences} out of 64")

if __name__ == "__main__":
    main()