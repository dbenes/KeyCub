import os
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
FILE_PATH = 'data.bin'
ENCRYPTION_KEY_SIZE = 32  # AES-256 requires a 32-byte key
MAX_ATTEMPTS = 5

def get_pin_from_user():
    """
    Prompt user to enter a 6-digit PIN code.
    """
    while True:
        pin = getpass("PIN: ").strip()  # Use getpass to hide PIN input
        if len(pin) == 6 and pin.isdigit():
            return pin
        print("Invalid PIN code. Must be exactly 6 digits.")

def get_service_details_from_user():
    """
    Prompt user to enter service details (name, username, password).
    """
    service = input("Enter the name of the service: ").strip()
    username = input("Enter the username: ").strip()
    password = input("Enter the password: ").strip()
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
        print("File wiped successfully.")
        sys.exit()  # Exit the program immediately after wiping the file
    else:
        print("No file to wipe.")

def main():

    print(f"  _  __          ___     _     ")
    print(f" | |/ /___ _  _ / __|  _| |__  ")
    print(f" | ' </ -_) || | (_| || | '_ \ ")
    print(f" |_|\_\___|\_, |\___\_,_|_.__/ ")
    print(f"           |__/                ")
    print(f"David Beneš 2025 (c)")
    print(f"\n")

    # Load existing data from file or initialize empty data
    data = load_from_file() or {'pin_hash': None, 'encrypted_services': None, 'salt': None}

    # Initialize the wrong attempt counter
    wrong_attempts = 0


    if 'pin_hash' in data and 'encrypted_services' in data and data['salt']:
        # File exists and salt is present, prompt for PIN verification
        while True:
            print("Enter your 6-digit PIN.")
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
                print("Password list:")
                for idx, service in enumerate(decrypted_services, start=1):
                    print(f"{idx}. {service['name']} ({service['timestamp']})\n   Username: {service['username']}\n   Password: {service['password']}\n")

                # Prompt user to choose next action
                while True:
                    action = input("Do you want to add, edit, delete, wipe the list, or exit? (add/edit/delete/wipe/exit): ").strip().lower()
                    if action == "add":
                        service, username, password, timestamp = get_service_details_from_user()
                        if not service or not username or not password:
                            print("Incomplete service details provided. Password not saved.")
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
                            service_number = int(input("Enter the number of the password you wish to edit: ").strip())
                            if service_number < 1 or service_number > len(decrypted_services):
                                raise ValueError
                            service = decrypted_services[service_number - 1]
                            username = input("Enter the new username: ").strip()
                            password = input("Enter the new password: ").strip()
                            if not username or not password:
                                print("Incomplete details provided. Password not updated.")
                            else:
                                service['username'] = username
                                service['password'] = password
                                service['timestamp'] = datetime.now().strftime('%d-%m-%Y')
                                print("Updated List:")
                                for idx, service in enumerate(decrypted_services, start=1):
                                    print(f"{idx}. {service['name']} ({service['timestamp']})\n   Username: {service['username']}\n   Password: {service['password']}\n")
                                print("Password updated successfully.")
                        except ValueError:
                            print("Invalid service number.")
                    elif action == "delete":
                        try:
                            service_number = int(input("Enter the number of the password you wish to delete: ").strip())
                            if service_number < 1 or service_number > len(decrypted_services):
                                raise ValueError
                            service = decrypted_services[service_number - 1]
                            print(f"Service to be deleted:\n {service['name']} ({service['timestamp']})\n   Username: {service['username']}\n   Password: {service['password']}\n")
                            confirm_delete = input("Are you sure you want to delete this password? (y/n): ").strip().lower()
                            if confirm_delete == 'y':
                                decrypted_services.pop(service_number - 1)
                                print("Password deleted successfully.")
                            else:
                                print("Deletion cancelled.")
                        except ValueError:
                            print("Invalid password number.")
                    elif action == "wipe":
                        confirm_wipe = input("Are you sure you want to wipe the whole password list? (y/n): ").strip().lower()
                        if confirm_wipe == 'y':
                            wipe_file()
                            data = {'pin_hash': None, 'encrypted_services': None, 'salt': None}
                            save_to_file(data)
                        else:
                            print("Wipe cancelled.")
                        continue
                    elif action == "exit":
                        print("Exiting...")
                        sys.exit()
                    else:
                        print("Invalid action. Please choose 'add', 'edit', 'delete', 'wipe', or 'exit'.")
                        continue

                    # Encrypt the updated services list
                    encrypted_services = encrypt_service(decrypted_services, key)
                    # Update the data dictionary with encrypted services
                    data['encrypted_services'] = urlsafe_b64encode(encrypted_services).decode('utf-8')
                    # Save updated data to file
                    save_to_file(data)
                    # Prompt to add/edit more services
                    more_actions = input("Do you want to add/edit more services? (yes/no): ").strip().lower()
                    if more_actions != 'yes':
                        break
                break
            else:
                # Wrong PIN
                wrong_attempts += 1
                print(f"Wrong pin. Attempt {wrong_attempts}/{MAX_ATTEMPTS}.")
                if wrong_attempts >= MAX_ATTEMPTS:
                    print("Maximum attempts reached. Wiping the file.")
                    wipe_file()

    else:
        # File does not exist or data is missing, create new data
        print("Please create a new KeyCub file by entering a 6-digit PIN.")
        pin = get_pin_from_user()

        # Initialize services list
        services = []

        while True:
            # Get service details
            service, username, password, timestamp = get_service_details_from_user()
            if not service or not username or not password:
                print("Incomplete service details provided. Exiting.")
                break

            # Add service details to list
            services.append({
                'name': service,
                'username': username,
                'password': password,
                'timestamp': timestamp
            })

            # Prompt to add more services
            add_more = input("Do you want to add more services? (yes/no): ").strip().lower()
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
