# ui.py

import tkinter as tk
from tkinter import messagebox, ttk

class CryptoUI:
    def __init__(self, root, encryption_manager, blockchain):
        self.root = root
        self.root.title("Advanced Crypto Project")

        self.encryption_manager = encryption_manager
        self.blockchain = blockchain

        # Frames
        self.input_frame = ttk.Frame(self.root, padding="10")
        self.input_frame.pack(fill=tk.X, padx=5, pady=5)

        self.action_frame = ttk.Frame(self.root, padding="10")
        self.action_frame.pack(fill=tk.X, padx=5, pady=5)

        self.block_view_frame = ttk.Frame(self.root, padding="10")
        self.block_view_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Widgets for encryption
        self.data_label = ttk.Label(self.input_frame, text="Data to Encrypt:")
        self.data_label.pack(side=tk.LEFT, padx=5)
        self.data_entry = ttk.Entry(self.input_frame, width=60)
        self.data_entry.pack(side=tk.LEFT, padx=5)

        self.encrypt_button = ttk.Button(self.action_frame, text="Encrypt & Add to Blockchain", command=self.encrypt_and_add)
        self.encrypt_button.pack(side=tk.LEFT, padx=5)

        # Widget for block selection
        self.block_label = ttk.Label(self.action_frame, text="Block Index to Decrypt:")
        self.block_label.pack(side=tk.LEFT, padx=5)
        self.block_index_var = tk.StringVar()
        self.block_index_entry = ttk.Entry(self.action_frame, textvariable=self.block_index_var, width=5)
        self.block_index_entry.pack(side=tk.LEFT, padx=5)

        self.decrypt_button = ttk.Button(self.action_frame, text="Decrypt", command=self.decrypt_from_block)
        self.decrypt_button.pack(side=tk.LEFT, padx=5)

        # Blockchain view
        self.blockchain_text = tk.Text(self.block_view_frame, height=20, wrap=tk.WORD)
        self.blockchain_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.update_blockchain_view()

    def encrypt_and_add(self):
        plaintext = self.data_entry.get().strip()
        if not plaintext:
            messagebox.showerror("Error", "Please enter some data.")
            return

        # Encrypt the data
        enc_dict = self.encryption_manager.encrypt_data(plaintext)
        
        # In a production scenario, you may store only the ciphertext and nonce in the chain. 
        # Additional metadata (timestamps, user IDs, etc.) can also be included.
        block_data = {
            'nonce': enc_dict['nonce'],
            'ciphertext': enc_dict['ciphertext']
        }

        new_block = self.blockchain.add_block(block_data)
        messagebox.showinfo("Success", f"Data encrypted and block #{new_block.index} added!")

        # Clear the input field
        self.data_entry.delete(0, tk.END)
        self.update_blockchain_view()

    def decrypt_from_block(self):
        try:
            index = int(self.block_index_var.get())
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid block index.")
            return

        if index <= 0 or index >= len(self.blockchain.chain):
            messagebox.showerror("Error", f"Block index out of range (1 to {len(self.blockchain.chain)-1}).")
            return

        target_block = self.blockchain.chain[index]
        block_data = target_block.data
        nonce = block_data['nonce']
        ciphertext = block_data['ciphertext']

        try:
            plaintext = self.encryption_manager.decrypt_data(nonce, ciphertext)
            messagebox.showinfo("Decrypted Data", f"Block #{index} plaintext: {plaintext}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt block #{index}: {str(e)}")

    def update_blockchain_view(self):
        self.blockchain_text.delete("1.0", tk.END)
        chain_json = self.blockchain.to_json()
        self.blockchain_text.insert(tk.END, chain_json)
