import os
import ctypes
import json
import uuid
from datetime import datetime
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import urlsafe_b64encode, urlsafe_b64decode
import sys
from getpass import getpass  # Import getpass for secure PIN entry

# Constants
FILE_PATH = 'keycub.bin'
ENCRYPTION_KEY_SIZE = 32  # AES-256 requires a 32-byte key
MAX_ATTEMPTS = 5
# ANSI color codes
GREY = '\033[90m'
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[93m'
BLUE = '\033[34m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
WHITE = '\033[97m'
RESET = '\033[0m'


def enable_virtual_terminal_processing():
    if os.name == 'nt':
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE = -11
        mode = ctypes.c_ulong()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        mode.value |= 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        kernel32.SetConsoleMode(handle, mode)

enable_virtual_terminal_processing()

def get_pin_from_user():
    """
    Prompt user to enter a 6-digit PIN code.
    """
    while True:
        pin = getpass(f"{WHITE}PIN: {MAGENTA}").strip()  # Use getpass to hide PIN input
        if len(pin) == 6 and pin.isdigit():
            return pin
        print(f"{RED}Invalid PIN code. Must be exactly 6 digits.{RESET}")

def get_service_details_from_user():
    """
    Prompt user to enter service details (name, username, password).
    """
    service = input(f"{WHITE}Enter the {YELLOW}new service name{RESET}: ").strip()
    username = input(f"{WHITE}Enter the {YELLOW}new username{RESET}: ").strip()
    password = input(f"{WHITE}Enter the {YELLOW}new password{RESET}: ").strip()
    timestamp = datetime.now().strftime('%d-%m-%Y')
    return service, username, password, timestamp

def hash_pin(pin, salt):
    """
    Hash the PIN using scrypt.
    """
    kdf = Scrypt(
        salt=salt,
        length=ENCRYPTION_KEY_SIZE,
        n=2 ** 14,
        r=8,
        p=1,
        backend=default_backend()
    )
    hashed_pin = kdf.derive(pin.encode())
    return hashed_pin

def generate_salt():
    """
    Generate a salt using scrypt.
    """
    salt = os.urandom(16)
    return salt

def generate_key_from_mac():
    """
    Generate a key from the MAC address using PBKDF2 with SHA-256.
    """
    mac_address = uuid.UUID(int=uuid.getnode()).hex[-12:]
    salt = mac_address.encode()
    kdf = Scrypt(
        salt=salt,
        length=ENCRYPTION_KEY_SIZE,
        n=2 ** 14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(salt)
    return key

def encrypt_service(service_details, key):
    """
    Encrypt the service details using AES CBC mode.
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(json.dumps(service_details).encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

def decrypt_service(encrypted_data, key):
    """
    Decrypt the encrypted service details using AES CBC mode.
    """
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return json.loads(unpadded_data.decode('utf-8'))

def save_to_file(data):
    """
    Save data to a .bin file encrypted with AES using the key derived from MAC address.
    """
    key = generate_key_from_mac()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(json.dumps(data).encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    with open(FILE_PATH, 'wb') as file:
        file.write(iv + encrypted_data)

def load_from_file():
    """
    Load data from a .bin file and decrypt using the key derived from MAC address.
    """
    if os.path.exists(FILE_PATH):
        key = generate_key_from_mac()
        try:
            with open(FILE_PATH, 'rb') as file:
                encrypted_data = file.read()
            iv = encrypted_data[:16]
            encrypted_data = encrypted_data[16:]
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
            return json.loads(unpadded_data.decode('utf-8'))
        except Exception as e:
            print("Your KeyCub file has been corrupted. Would you like to wipe it? (y/n)")
            response = input().strip().lower()
            if response == 'y':
                wipe_file()
                return None
            else:
                print("Exiting without wiping the file.")
                sys.exit()
    else:
        return None

def wipe_file():
    """
    Wipe the contents of the .bin file.
    """
    if os.path.exists(FILE_PATH):
        os.remove(FILE_PATH)
        print(f"{WHITE}File wiped successfully.{RESET}")
        sys.exit()  # Exit the program immediately after wiping the file
    else:
        print("No file to wipe.")

def main():

    print(f"{MAGENTA}    __ __                  ______            __  ")
    print(f"   / //_/  ___    __  __  / ____/  __  __   / /_ ")
    print(f"{CYAN}  / ,<    / _ \  / / / / / /      / / / /  / __ \ ")
    print(f" / /| |  /  __/ / /_/ / / /___   / /_/ /  / /_/ /")
    print(f"{YELLOW}/_/ |_|  \___/  \__, /  \____/   \__,_/  /_.___/ ")
    print(f"               /____/                                    ")
    print(f"{GREY}David Beneš 2025 \u00A9{RESET}")
    print(f"\n")


    # Load existing data from file or initialize empty data
    data = load_from_file() or {'pin_hash': None, 'encrypted_services': None, 'salt': None}

    # Initialize the wrong attempt counter
    wrong_attempts = 0


    if 'pin_hash' in data and 'encrypted_services' in data and data['salt']:
        # File exists and salt is present, prompt for PIN verification
        while True:
            pin = get_pin_from_user()

            # Verify PIN
            salt = urlsafe_b64decode(data['salt'].encode('utf-8'))
            hashed_pin = hash_pin(pin, salt)
            if hashed_pin == urlsafe_b64decode(data['pin_hash'].encode('utf-8')):
                # PIN is correct
                if wrong_attempts > 0:
                    print(f"Number of failed attempts: {wrong_attempts}")
                # Reset wrong attempts counter
                wrong_attempts = 0

                # Decrypt the services
                key = hashed_pin[:ENCRYPTION_KEY_SIZE]
                encrypted_services = urlsafe_b64decode(data['encrypted_services'].encode('utf-8'))
                decrypted_services = decrypt_service(encrypted_services, key)
                print(f"\n{WHITE}Saved Passwords{RESET}")
                print(f"{WHITE}----------------{RESET}")
                for idx, service in enumerate(decrypted_services, start=1):
                    print(f"{MAGENTA}{idx}.{WHITE} {service['name']} ({service['timestamp']}){RESET}\n   Username: {service['username']}\n   Password: {service['password']}\n")

                # Prompt user to choose next action
                while True:
                    action = input(f"{WHITE}Do you want to add, edit, delete or wipe the list?{RESET} (add/edit/delete/wipe/exit):").strip().lower()
                    if action == "add":
                        service, username, password, timestamp = get_service_details_from_user()
                        if not service or not username or not password:
                            print(f"{RED} Incomplete service details provided. Password not saved.{RESET}")
                            continue
                        # Add new service to the decrypted services list
                        decrypted_services.append({
                            'name': service,
                            'username': username,
                            'password': password,
                            'timestamp': timestamp
                        })
                    elif action == "edit":
                        try:
                            service_number = int(input(f"{WHITE}Enter the {MAGENTA}number{WHITE} of the service you wish to edit: {RESET}").strip())
                            if service_number < 1 or service_number > len(decrypted_services):
                                raise ValueError
                            service = decrypted_services[service_number - 1]
                            print(f"\n{YELLOW}Service to be edited:{WHITE}\n   {service['name']} ({service['timestamp']}){RESET}\n   Username: {service['username']}\n   Password: {service['password']}\n{RESET}")
                            username = input(f"{WHITE}Enter the {YELLOW}updated username{RESET}{WHITE}: {RESET}").strip()
                            password = input(f"{WHITE}Enter the {YELLOW}updated password{RESET}{WHITE}: {RESET}").strip()
                            if not username or not password:
                                print(f"{RED}Incomplete details provided. Password not updated.{RESET}")
                            else:
                                service['username'] = username
                                service['password'] = password
                                service['timestamp'] = datetime.now().strftime('%d-%m-%Y')
                                print(f"{YELLOW}Updated List:{RESET}")
                                for idx, service in enumerate(decrypted_services, start=1):
                                    print(f"{WHITE}{idx}. {service['name']} ({service['timestamp']}){RESET}\n   Username: {service['username']}\n   Password: {service['password']}\n")
                                print(f"{YELLOW}Password updated successfully.{RESET}")
                        except ValueError:
                            print(f"{RED}Invalid service number.{RESET}")
                    elif action == "delete":
                        try:
                            service_number = int(input(f"{WHITE}Enter the {MAGENTA}number{WHITE} of the password to be deleted: {RESET}").strip())
                            if service_number < 1 or service_number > len(decrypted_services):
                                raise ValueError
                            service = decrypted_services[service_number - 1]
                            print(f"{YELLOW}Service to be deleted:\n {service['name']} ({service['timestamp']})\n   Username: {service['username']}\n   Password: {service['password']}\n{RESET}")
                            confirm_delete = input(f"{YELLOW}Are you sure you want to delete this password?{RESET} (y/n): ").strip().lower()
                            if confirm_delete == 'y':
                                decrypted_services.pop(service_number - 1)
                                print(f"{YELLOW}Password deleted successfully.{RESET}")
                            else:
                                print(f"{MAGENTA}Deletion cancelled.{RESET}")
                        except ValueError:
                            print(f"{RED}Invalid password number.{RESET}")
                    elif action == "wipe":
                        confirm_wipe = input(f"{YELLOW}Are you sure you want to wipe the whole password list?{RESET} (y/n): ").strip().lower()
                        if confirm_wipe == 'y':
                            wipe_file()
                            data = {'pin_hash': None, 'encrypted_services': None, 'salt': None}
                            save_to_file(data)
                        else:
                            print(f"{MAGENTA}Wipe cancelled.{RESET}")
                        continue
                    elif action == "exit":
                        print(f"{GREY}Exiting...{RESET}")
                        sys.exit()
                    else:
                        print(f"{RED}Invalid action. Please type 'add', 'edit', 'delete', 'wipe', or 'exit'.{RESET}")
                        continue

                    # Encrypt the updated services list
                    encrypted_services = encrypt_service(decrypted_services, key)
                    # Update the data dictionary with encrypted services
                    data['encrypted_services'] = urlsafe_b64encode(encrypted_services).decode('utf-8')
                    # Save updated data to file
                    save_to_file(data)
                    # Prompt to add/edit more services
                    more_actions = input(f"{WHITE}Do you want to make more changes?{RESET} (yes/no): ").strip().lower()
                    if more_actions != 'yes':
                        break
                break
            else:
                # Wrong PIN
                wrong_attempts += 1
                print(f"{RED}Wrong PIN.{RESET} Attempt {wrong_attempts}/{MAX_ATTEMPTS}.")
                if wrong_attempts >= MAX_ATTEMPTS:
                    print(f"{RED}Maximum attempts reached. Wiping the file.{RESET}")
                    wipe_file()

    else:
        # File does not exist or data is missing, create new data
        print(f"{WHITE}Create a new KeyCub file by entering a 6-digit PIN.{RESET}")
        pin = get_pin_from_user()

        # Initialize services list
        services = []

        while True:
            # Get service details
            service, username, password, timestamp = get_service_details_from_user()
            if not service or not username or not password:
                print(f"{GREY}Incomplete service details provided. Exiting.{RESET}")
                break

            # Add service details to list
            services.append({
                'name': service,
                'username': username,
                'password': password,
                'timestamp': timestamp
            })

            # Prompt to add more services
            add_more = input(f"{WHITE}Do you want to add more services?{RESET} (yes/no): ").strip().lower()
            if add_more != 'yes':
                break

        # Hash PIN and encrypt services data
        salt = generate_salt()  # Generate a salt using scrypt
        pin_hash = hash_pin(pin, salt)
        key = pin_hash[:ENCRYPTION_KEY_SIZE]
        encrypted_services = encrypt_service(services, key)

        # Save to file
        data['pin_hash'] = urlsafe_b64encode(pin_hash).decode('utf-8')
        data['encrypted_services'] = urlsafe_b64encode(encrypted_services).decode('utf-8')
        data['salt'] = urlsafe_b64encode(salt).decode('utf-8')
        save_to_file(data)
        print("Data saved successfully.")

if __name__ == "__main__":
    main()
