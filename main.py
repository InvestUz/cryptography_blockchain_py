# main.py

import tkinter as tk
from encryption import EncryptionManager
from blockchain import Blockchain
from ui import CryptoUI

def main():
    # Initialize core components
    encryption_manager = EncryptionManager()
    blockchain = Blockchain()

    # Initialize and run Tkinter UI
    root = tk.Tk()
    app = CryptoUI(root, encryption_manager, blockchain)
    root.mainloop()

if __name__ == '__main__':
    main()
