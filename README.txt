# Hash-Cracker-
This tool provides both hashing and cracking functionalities for passwords using various algorithms. It’s designed for educational purposes to demonstrate password security, hashing techniques, and password-cracking methods.  Please use responsibly and ensure compliance with all ethical and legal guidelines.

**Features**:
Hash Generation: Generates hashed passwords using algorithms like MD5, SHA-256, bcrypt, and more.
Password Cracking: Cracks hashed passwords using a dictionary attack with multithreaded support.
Customizable Algorithms: Supports native and SQL-based hashing algorithms, as well as advanced methods like PBKDF2 and bcrypt.
Multithreading: Leverages multiple threads to speed up the cracking process.
Salted Hashing: Includes support for salted hashing functions where a username can be used as a salt for enhanced security.

**Requirements**
Python 3.x
passlib library for advanced hashing algorithms

**Install dependencies:**
pip install passlib

**Usage**
Clone the repository:
  git clone https://github.com/yourusername/repository-name
  cd repository-name
Run the script with the required parameters.

**Command-Line Arguments**
Argument   Description
-m,       --mode	Mode of operation: hashing or cracking.
-p,       --password	Password to hash (required for hashing mode).
-s,       --passwordhash	Hash of the password to crack (required for cracking mode).
-a,       --hashing_algorithm	Algorithm to use for hashing or cracking (e.g., md5, sha256).
-w,       --wordlist	Path to the dictionary file for cracking mode.
-t,       --num-threads	Number of threads for cracking (default: 1).
-u,       --username_salt	Username to be used as a salt in specific hashing functions.

**Example Commands**
**Hashing Mode:**
python3 tool.py -m hashing -p "your_password" -a "sha256"

**Cracking Mode:**
python3 tool.py -m cracking -s "<hashed_password>" -a "sha256" -w "wordlist.txt" -t 4

Sample Output
base64:       cGFzc3dvcmQxMjM0Kw==
hex:          70617373776f7264313233342b
md4:          74d35e28ba14a0b99dff14cb45b3a9e3
md5:          482c811da5d5b4bc6d497ffa98491e38
...
bcrypt:       $2b$12$0ktEh5RIaM7eUi5DozSDNuIGftK1WPPNoU7D8DxXr7wCR/W/nrrLO  1.532 seconds


**Code Structure**
Main Functions
password_hash(password): Handles password encoding and hashing for different algorithms, including base64, hex, MD5, SHA-256, and advanced algorithms like bcrypt and pbkdf2.
password_crack(password_hash, hashing_algorithm, hashing_algorithms_1, hashing_algorithms_2, username_salt): Implements password cracking by comparing hashes from a wordlist.
main(mode, password, passwordhash, hashing_algorithm, n_threads, wordlist, username_salt): Sets up and coordinates hashing and cracking modes.

**Threading**
Uses a queue and threading to speed up the cracking process. Each thread pulls from the queue and attempts to match the password hash.

**Troubleshooting**
Ensure the wordlist file is in the specified path.
If using salted hashes, ensure the salt (username) is correctly provided.
Confirm compatibility of the hashing algorithm with the provided hash.

**Legal Notice**
This tool is intended solely for educational and ethical research purposes. Misuse of this tool may lead to severe legal consequences. Always obtain permission before attempting to crack any password.
