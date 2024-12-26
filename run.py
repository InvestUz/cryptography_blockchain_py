# run.py

import subprocess
import sys

if __name__ == "__main__":
    # Optional: install dependencies automatically
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    
    # Now run the main script
    import main
    main.main()
