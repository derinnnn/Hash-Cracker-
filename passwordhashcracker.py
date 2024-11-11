#!/usr/bin/python3

import binascii
import hashlib
from passlib.hash import mysql323, mysql41, mssql2000, mssql2005, postgres_md5, oracle10, oracle11
from passlib.hash import lmhash, nthash, msdcc, msdcc2
from passlib.hash import pbkdf2_sha256, pbkdf2_sha512, sha512_crypt, sha256_crypt, bcrypt
from os import urandom
import time
import argparse, threading, queue, sys
from passlib.context import CryptContext


def password_hash(password):
    utf_password = password.encode("UTF-8")

    base64_password = binascii.b2a_base64(utf_password)
    hex_password = binascii.b2a_hex(utf_password)
    print("base64: ", base64_password.decode("UTF-8").strip("\n"))
    print("hex: ", hex_password.decode("UTF-8").strip("\n"))
    print("\n")

    hashing_algorithms = ('md4', 'md5', 'sha1', 'sha224', 'sha3_224', 'sha256', 'sha3_256', 'sha512', 'sha3_512')
    for hashing_algorithm in hashing_algorithms:
        password_hash = hashlib.new(hashing_algorithm, utf_password).hexdigest()
        print(hashing_algorithm, ": ", password_hash)
    print("\n")

    print("mysql323        :", mysql323.hash(utf_password))
    print("mysql41         :", mysql41.hash(utf_password))
    print("mssql2000       :", mssql2000.hash(utf_password))
    print("mssql2005       :", mssql2005.hash(utf_password))
    print("oracle11        :", oracle11.hash(utf_password))
    print("\n")

    salt = urandom(32)
    decoded_salt = binascii.b2a_base64(salt).decode().strip()
    decoded_salt = decoded_salt.replace("+", ",").replace("=", "")
    print("salt   :", decoded_salt)
    print("\n")

    T1 = time.time()
    print("pbkdf2 :", pbkdf2_sha256.hash(utf_password, rounds=101000, salt=salt), time.time() - T1, "seconds")

    T1 = time.time()
    print("pbkdf2 :", pbkdf2_sha512.hash(utf_password, rounds=101000, salt=salt), time.time() - T1, "seconds")

    sha512_crypt_salt = decoded_salt[:16]

    T1 = time.time()
    print("sha512_crypt :", sha512_crypt.hash(utf_password, rounds=8000, salt=sha512_crypt_salt), time.time() - T1, "seconds")

    T1 = time.time()
    print("sha256_crypt :", sha256_crypt.hash(utf_password, rounds=8000, salt=sha512_crypt_salt), time.time() - T1, "seconds")

    bsd_salt = decoded_salt[:22]
    bsd_salt = bsd_salt.replace(bsd_salt[21], ".")
    valid_salt = bsd_salt[:22]

    T1 = time.time()
    print("bcrypt :", bcrypt.hash(utf_password, rounds=14, salt=valid_salt), time.time() - T1, "seconds")


def password_crack(password_hash, hashing_algorithm, hashing_algorithms_1, hashing_algorithms_2, username_salt):
    global q
    while not q.empty():
        try:
            password = q.get()
            if hashing_algorithm in hashing_algorithms_1:
                if hashlib.new(hashing_algorithm, password.encode("UTF-8")).hexdigest() == password_hash:
                    print("\nFound credentials:", q.qsize(), password)
                    q.task_done()
                    with q.mutex:
                        q.queue.clear()
                        q.all_tasks_done.notify_all()
                        q.unfinished_tasks = 0
                    return

            elif hashing_algorithm in hashing_algorithms_2:
                pwd_context = CryptContext(schemes=[hashing_algorithm])
                try:
                    if pwd_context.verify(password, password_hash):
                        print("\nFound credentials:", q.qsize(), password)
                        q.task_done()
                        with q.mutex:
                            q.queue.clear()
                            q.all_tasks_done.notify_all()
                            q.unfinished_tasks = 0
                        return
                except:
                    pass

            else:
                pwd_context = CryptContext(schemes=[hashing_algorithm])
                if pwd_context.verify(password + username_salt, password_hash):
                    print("\nFound credentials:", q.qsize(), password)
                    q.task_done()
                    with q.mutex:
                        q.queue.clear()
                        q.all_tasks_done.notify_all()
                        q.unfinished_tasks = 0
                    return

        except:
            pass
        q.task_done()


q = queue.Queue()
def main(mode, password, passwordhash, hashing_algorithm, n_threads, wordlist, username_salt):
    hashing_algorithms_1 = ['md4', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
    hashing_algorithms_2 = ['lmhash', 'nthash', 'pbkdf2_sha256', 'pbkdf2_sha512', 'sha256_crypt', 'sha512_crypt', 'bcrypt', 'mysql323', 'mysql41', 'mssql2000', 'mssql2005', 'oracle10']
    hashing_algorithms_3 = ['msdcc', 'msdcc2', 'postgres_md5', 'oracle10']

    if mode == 'hashing':
        password_hash(password)

    elif mode == 'cracking':
        global q
        try:
            with open(wordlist, "r") as wordlist_items:
                for wordlist_item in wordlist_items:
                    q.put(wordlist_item.strip())
        except:
            print("\nError: dictionary file not found.\n")
            sys.exit()

        if hashing_algorithm not in hashing_algorithms_1 and hashing_algorithm not in hashing_algorithms_2 and hashing_algorithm not in hashing_algorithms_3:
            print("\nError: invalid hashing algorithm.\n")
            sys.exit()

        if hashing_algorithm in hashing_algorithms_3 and username_salt is None:
            print("\nError: hashing algorithm requires a username as a salt.\n")
            sys.exit()

        for i in range(n_threads):
            worker = threading.Thread(target=password_crack, args=(passwordhash, hashing_algorithm, hashing_algorithms_1, hashing_algorithms_2, username_salt))
            worker.daemon = True
            worker.start()

        q.join()
    else:
        print("\nError: mode can be only hashing or cracking.\n")
        sys.exit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="password hash generator and cracker")
    parser.add_argument("-m", "--mode", help="hashing or cracking mode")
    parser.add_argument("-p", "--password", help="password to be hashed")
    parser.add_argument("-s", "--passwordhash", help="password hash to be cracked")
    parser.add_argument("-a", "--hashing_algorithm", help="hashing algorithm to be used for cracking")
    parser.add_argument("-w", "--wordlist", help="Dictionary file to be used for password hash cracking")
    parser.add_argument("-t", "--num-threads", help="Number of threads to use to brute force the login-page", default=1, type=int)
    parser.add_argument("-u", "--username_salt", help="username to be added as a salt in hashing functions like mscache, postgresql, and oracle")

    args = parser.parse_args()
    mode = args.mode
    password = args.password
    passwordhash = args.passwordhash
    hashing_algorithm = args.hashing_algorithm
    wordlist = args.wordlist
    num_threads = args.num_threads
    username_salt = args.username_salt

    main(mode=mode, password=password, passwordhash=passwordhash, hashing_algorithm=hashing_algorithm, n_threads=num_threads, wordlist=wordlist, username_salt=username_salt)
    q.join()
    sys.exit()
