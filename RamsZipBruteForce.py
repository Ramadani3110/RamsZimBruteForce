import zipfile
import itertools
import string
from multiprocessing import Pool, Manager
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import argparse
import os
from tqdm import tqdm

def test_password_worker(args):
    zip_path, password = args
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.setpassword(password.encode())
            zip_ref.read(zip_ref.namelist()[0])
            return password
    except:
        return None


class RamsZipBruteForce:
    def __init__(self, zip_path):
        self.zip_path = zip_path
        self.found_password = None
        self.attempts = 0 

    def brute_force(self, min_length=1, max_length=4, charset=None, num_processes=3):
        if charset is None:
            charset = string.ascii_lowercase + string.digits

        manager = Manager()
        stop_flag = manager.Event()
        attempts_counter = manager.Value('i', 0)

        print(f"[INFO] Starting brute force: {self.zip_path}")
        print(f"[INFO] Charset: {charset}")
        print(f"[INFO] Length range: {min_length}-{max_length}")
        print(f"[INFO] Using {num_processes} processes")

        for length in range(min_length, max_length + 1):
            if stop_flag.is_set():
                break

            print(f"\n[INFO] Trying length: {length}")
            combos = (''.join(p) for p in itertools.product(charset, repeat=length))
            total = len(charset) ** length
            tasks = ((self.zip_path, pwd) for pwd in combos)

            with Pool(processes=num_processes) as pool:
                with tqdm(total=total, desc=f"Len {length}", ncols=80) as pbar:
                    try:
                        for result in pool.imap_unordered(test_password_worker, tasks, chunksize=100):
                            attempts_counter.value += 1
                            pbar.update(1)

                            if result:
                                self.found_password = result
                                stop_flag.set()
                                pool.terminate()
                                pool.join()
                                print(f"\n[SUCCESS] Password found: {result}")
                                return result

                    except KeyboardInterrupt:
                        stop_flag.set()
                        pool.terminate()
                        pool.join()
                        print("\n[EXIT] Brute force stopped by user.")
                        return None

        self.attempts = attempts_counter.value

        print("[INFO] Brute force completed. Password not found.")
        return None

    def dictionary(self, wordlist_path, num_processes=3):
        """Perform dictionary attack using wordlist file"""
        print(f"[INFO] Starting dictionary attack on {self.zip_path}")
        print(f"[INFO] Using wordlist: {wordlist_path}")

        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                with ThreadPoolExecutor(max_workers=num_processes) as executor:
                    passwords = []
                    futures = []

                    for line in f:
                        password = line.strip()
                        if not password:
                            continue

                        passwords.append(password)

                        # Submit in batch
                        if len(passwords) >= 1000:
                            futures = {
                                executor.submit(test_password_worker, (self.zip_path, pwd)): pwd
                                for pwd in passwords
                            }

                            for future in as_completed(futures):
                                result = future.result()
                                self.attempts += 1
                                if result:
                                    self.found_password = result
                                    print(f"\n[SUCCESS] Password found: {result}")
                                    print(f"[INFO] Attempts made: {self.attempts}")
                                    return result
                                if self.attempts % 1000 == 0:
                                    print(f"[INFO] Tried {self.attempts} passwords...")

                            passwords = []  # reset batch

                    # Sisa password terakhir
                    if passwords:
                        futures = {
                            executor.submit(test_password_worker, (self.zip_path, pwd)): pwd
                            for pwd in passwords
                        }

                        for future in as_completed(futures):
                            result = future.result()
                            self.attempts += 1
                            if result:
                                self.found_password = result
                                print(f"\n[SUCCESS] Password found: {result}")
                                print(f"[INFO] Attempts made: {self.attempts}")
                                return result
                            if self.attempts % 1000 == 0:
                                print(f"[INFO] Tried {self.attempts} passwords...")

        except FileNotFoundError:
            print(f"[ERROR] Wordlist file not found: {wordlist_path}")
            return None
        
        print("[INFO] Dictionary attack completed. Password not found.")
        return None

def main():
    parser = argparse.ArgumentParser(
        description= "RamsZipBruteForce",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
        Examples:
            python3 RamsZipBruteForce.py file.zip -b -min 1 -max 4          # Brute force attack with limit length
            python3 RamsZipBruteForce.py file.zip -b                        # Brute force attack
            python3 RamsZipBruteForce.py file.zip -b -c abc                 # Brute force using custom character
            python3 RamsZipBruteForce.py file.zip -b -t 4                   # Brute force using custom threads
            python3 RamsZipBruteForce.py file.zip -d -p wordlist.txt        # External wordlist
        '''
    )
    parser.add_argument('zipfile', nargs='?', help='Path to ZIP file to crack')
    parser.add_argument('-b', '--brute-force', action='store_true',
                    help='Perform brute force attack')
    parser.add_argument('-min', '--min-length', type=int, default=1,
                       help='Minimum password length for brute force (default: 1)')
    parser.add_argument('-max', '--max-length', type=int, default=4,
                       help='Maximum password length for brute force (default: 4)')
    parser.add_argument('-c', '--charset', default='',
                       help='Custom character set for brute force')
    parser.add_argument('-t', '--threads', type=int ,default=3,
                       help='Number of threads (default: 3)')
    parser.add_argument('-p', '--passwords', metavar='FILE', 
                       help='Path to password wordlist file')
    parser.add_argument('-d', '--dictionary', action='store_true',
                    help='Perform dictionary attack')

    args = parser.parse_args()

    print('''
  ___               _____      ___          _       ___               
 | _ \__ _ _ __  __|_  (_)_ __| _ )_ _ _  _| |_ ___| __|__ _ _ __ ___ 
 |   / _` | '  \(_-</ /| | '_ \ _ \ '_| || |  _/ -_) _/ _ \ '_/ _/ -_)
 |_|_\__,_|_|_|_/__/___|_| .__/___/_|  \_,_|\__\___|_|\___/_| \__\___|
                         |_|                      ZIP Brute Force v1.0              
''')
    
    if not args.zipfile:
        print("Error: ZIP file path is required!")
        print(parser.print_help())
        return

    if not os.path.exists(args.zipfile):
        print(f"Error: Invalid ZIP path : {args.zipfile}")
        print(parser.print_help())
        return
    
    try:
        with zipfile.ZipFile(args.zipfile, 'r') as test_zip:
            pass
    except zipfile.BadZipFile:
        print(f"Error: Invalid ZIP file: {args.zipfile}")
        print(parser.print_help())
        return
    
    bruteforcer = RamsZipBruteForce(args.zipfile)
    start_time = time.time()
    result = None

    if args.threads <= 1:
        print("[ERROR] Threads must more than 1")
        print("[ERROR] For example using 2 threads")
        print(f"[INFO] You current threads {args.threads}")
        return

    if args.brute_force:

        charset = args.charset if args.charset else string.ascii_lowercase + string.digits
        print(f"[START] Starting brute force attack: {args.zipfile}")
        print(f"[START] Length range: {args.min_length} - {args.max_length}")
        print(f"[START] Starting brute force attack: {args.zipfile}")
       
        result = bruteforcer.brute_force(
            args.min_length, args.max_length, charset, args.threads
        )
    elif args.passwords and args.dictionary:
        if not os.path.exists(args.passwords):
            print(f"[INFO] Password file not found: {args.passwords}")
            return
        
        print(f"[INFO] Using existing password list: {args.passwords}")

        print(f"[INFO] Starting dictionary attack: {args.zipfile} with wordlist: {args.passwords}")
        result = bruteforcer.dictionary(args.passwords, args.threads)

    end_time =  time.time()

    if result:
        print(f"\n[SUCCESS] Password Found: {result}")
        print(f"\n[INFO] Time taken: {end_time - start_time:.2f} seconds")
        print(f"\n[INFO] Total attemps: {bruteforcer.attempts}")
    else:
        print(f"\n[INFO] Password not found")
        print(f"\n[INFO] Time taken: {end_time - start_time:.2f} seconds")
        print(f"\n[INFO] Total attempts: {bruteforcer.attempts}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[EXIT] Brute force stopped")