# blockchain.py

import hashlib
import json
import time

class Block:
    def __init__(self, index, data, previous_hash):
        self.index = index
        self.timestamp = time.time()
        self.data = data  # Could store { 'nonce', 'ciphertext', ... } here
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.timestamp}{self.data}{self.previous_hash}"
        return hashlib.sha256(block_string.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = []
        # Create the genesis block
        genesis_block = Block(index=0, data="Genesis Block", previous_hash="0")
        self.chain.append(genesis_block)

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, data):
        new_block = Block(
            index=len(self.chain),
            data=data,
            previous_hash=self.get_latest_block().hash
        )
        self.chain.append(new_block)
        return new_block

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # Check current block hash
            if current_block.hash != current_block.calculate_hash():
                return False

            # Check chain continuity
            if current_block.previous_hash != previous_block.hash:
                return False

        return True

    def to_json(self):
        """
        Serialize the entire chain to JSON for logging or storage.
        """
        chain_data = []
        for block in self.chain:
            chain_data.append({
                'index': block.index,
                'timestamp': block.timestamp,
                'data': block.data,
                'previous_hash': block.previous_hash,
                'hash': block.hash
            })
        return json.dumps(chain_data, indent=2)
