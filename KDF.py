import numpy as np
from bitarray import bitarray

class SimpleSponge:
    def __init__(self, state_size=256, block_size=64):
        """
        Initialize a sponge function with a given internal state size and block size.

        Parameters:
        - state_size: Size of the internal state in bits.
        - block_size: Size of an absorption block in bits.
        """
        self.state_size = state_size
        self.block_size = block_size
        self.state = np.zeros(state_size, dtype=np.uint8)  # Internal state in bits

    def _absorb_block(self, block_bits):
        """
        Absorb a block of bits into the internal state by applying XOR.
        """
        for i in range(len(block_bits)):
            self.state[i % self.state_size] ^= block_bits[i]

        # Simple transformation: a circular shift on the state to mix it
        self.state = np.roll(self.state, 1)

    def absorb(self, input_data):
        """
        Absorb the input data in blocks into the internal state.

        Parameter:
        - input_data: The input data as a bitarray.
        """
        # Split the data into blocks of the specified size
        for i in range(0, len(input_data), self.block_size):
            block = input_data[i:i+self.block_size]
            # Pad with zeros if the block is incomplete
            if len(block) < self.block_size:
                block.extend([0] * (self.block_size - len(block)))
            # Absorb the block into the state
            self._absorb_block(block)

    def squeeze(self, output_length):
        """
        Squeeze the internal state to produce an output of the desired length.

        Parameter:
        - output_length: The length of the output in bits.

        Returns:
        - A bitarray containing the squeezed output.
        """
        output = bitarray()
        while len(output) < output_length:
            # Add a part of the current state to the output
            output.extend(self.state[:min(output_length - len(output), self.state_size)])
            # Apply a transformation to further "mix" the state
            self.state = np.roll(self.state, 3)  # Circular shift
            self.state = ~self.state  # Bitwise NOT for simple modification
        return output[:output_length]  # Truncate to exact length

# Main function to derive a key from a password

def derive_key_from_password(password, output_length=256):
    """
    Derive a key from a password using a sponge function.

    Parameters:
    - password (str): Password provided by the user.
    - output_length (int): Length of the derived key in bits (default 256).

    Returns:
    - Derived key as a hexadecimal string.
    """
    # Convert the password to bits
    input_bits = bitarray()
    input_bits.frombytes(password.encode('utf-8'))

    # Initialize and absorb the password into the sponge function
    sponge = SimpleSponge()
    sponge.absorb(input_bits)

    # Squeeze to obtain the derived key
    derived_key_bits = sponge.squeeze(output_length)

    # Return the derived key in hexadecimal format
    return derived_key_bits.tobytes().hex()
