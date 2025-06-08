# RamsZipBruteForce

is a simple tool to perform **brute force** or **dictionary attacks** on password protected ZIP files. This tool supports multiprocessing and multithreading to speed up the password finding process.

---

## 🔧 Cara Menjalankan

### 1. Instalasi Paket yang Dibutuhkan
```bash
pip install tqdm
```
### 2. Basic Usage
```bash
sage: RamsZipBruteForce.py [-h] [-b] [-min MIN_LENGTH] [-max MAX_LENGTH] [-c CHARSET] [-t THREADS] [-p FILE] [-d] [zipfile]

RamsZipBruteForce

positional arguments:
  zipfile               Path to ZIP file to crack

options:
  -h, --help            show this help message and exit
  -b, --brute-force     Perform brute force attack
  -min MIN_LENGTH, --min-length MIN_LENGTH
                        Minimum password length for brute force (default: 1)
  -max MAX_LENGTH, --max-length MAX_LENGTH
                        Maximum password length for brute force (default: 4)
  -c CHARSET, --charset CHARSET
                        Custom character set for brute force
  -t THREADS, --threads THREADS
                        Number of threads (default: 3)
  -p FILE, --passwords FILE
                        Path to password wordlist file
  -d, --dictionary      Perform dictionary attack

        Examples:
            python3 RamsZipBruteForce.py file.zip -b -min 1 -max 4          # Brute force attack with limit length
            python3 RamsZipBruteForce.py file.zip -b                        # Brute force attack
            python3 RamsZipBruteForce.py file.zip -b -c abc                 # Brute force using custom character
            python3 RamsZipBruteForce.py file.zip -b -t 4                   # Brute force using custom threads
            python3 RamsZipBruteForce.py file.zip -d -p wordlist.txt        # External wordlist
```

### 3. How To Use
#### 1. Brute Force Attack
- Brute force with min password lengh 1 and max length 4 and using 4 threads:
```bash
python3 RamsZipBruteForce.py file.zip -b -min 1 -max 4 -t 4
```
- Brute force using custom charset:
```bash
python3 RamsZipBruteForce.py file.zip -b -c abc
```
- Brute force using default options:
```bash 
python3 RamsZipBruteForce.py file.zip -b
```
#### 2. Dictionary Attack
- Using wordlist and 4 threads:
```bash
python3 RamsZipBruteForce.py file.zip -d -p wordlist.txt -t 4
```

### Notes:
- Zip file encypted with AES can't opened by this sript
- This tool is intended for testing, security research, or personal file recovery. Do not use it for illegal activities.
