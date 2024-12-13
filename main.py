import os
import csv
import ctypes
import json
import subprocess
from datetime import datetime
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import urlsafe_b64encode, urlsafe_b64decode
import sys
import msvcrt  # Import msvcrt for Windows-specific console input handling
import time


# Constants declared.
FILE_PATH = 'MyKeyCub.bin'  # password log file
ENCRYPTION_KEY_SIZE = 32   # AES-256 requires a 32-byte key
MAX_ATTEMPTS = 5  # maximum number of failed attempts before wipe

# ANSI color codes for use throughout application.
GREY = '\033[90m'
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[93m'
BLUE = '\033[34m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
WHITE = '\033[97m'
RESET = '\033[0m'


def enable_virtual_terminal_processing():  # virtual processor for loading application into Windows Terminal.
    if os.name == 'nt':
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        mode.value |= 0x0004
        kernel32.SetConsoleMode(handle, mode)


enable_virtual_terminal_processing()  # run virtual terminal at beginning of application.


def import_from_csv(filepath, decrypted_services):  # defining the function for importing .csv files.
    try:
        with open(filepath, 'r', newline='', encoding='utf-8-sig') as csvfile:
            csvreader = csv.reader(csvfile)
            next(csvreader)  # Skip the header row
            for row in csvreader:
                if all(cell.strip() == "" for cell in row):
                    break  # Stop if the row is entirely blank
                if len(row) < 4:
                    continue  # Skip rows that do not have enough columns
                service = row[0]
                username = row[2]
                password = row[3]
                timestamp = datetime.now().strftime('%d-%b-%Y')
                decrypted_services.append({
                    'name': service,
                    'username': username,
                    'password': password,
                    'timestamp': timestamp
                })
        print_all_passwords(decrypted_services)
        print(f"{MAGENTA}\nPasswords imported successfully.\n{RESET}")
    except FileNotFoundError:
        print(f"{RED}\nError: File not found.\n{RESET}")
    except UnicodeDecodeError as e:
        print(f"{RED}\nAn error occurred while importing CSV: {e}\n{RESET}")
    except Exception as e:
        print(f"{RED}\nAn unexpected error occurred while importing CSV: {e}\n{RESET}")


def get_pin_from_user():  # function to receive pin code from user.
    pin = ''
    sys.stdout.write(f"{WHITE}PIN: {MAGENTA}")
    sys.stdout.flush()

    while True:
        ch = msvcrt.getwch()  # Get a single characters from user entry using msvcrt.
        if ch.isdigit() and len(pin) < 6:
            pin += ch
            sys.stdout.write('⬤')  # printing circle instead of number.
            sys.stdout.flush()
        elif (ch == '\r' or ch == '\n') and len(pin) == 6:  # Handle Enter key press only if PIN is 6 digits
            break
        elif ch == '\b':  # Handle Backspace key press.
            if pin:
                pin = pin[:-1]
                sys.stdout.write('\b \b')  # Move cursor back one character, print space, move cursor back again
                sys.stdout.flush()
        else:
            continue

    print(RESET)  # Reset color after PIN entry
    if len(pin) == 6:
        return pin
    print(f"{RED}Invalid PIN code. Must be exactly 6 digits.{RESET}")


def get_usb_controller_device_id():
    try:
        # PowerShell command to get a single USB Controller DeviceID
        command = "(Get-WmiObject Win32_USBController | Select-Object -ExpandProperty DeviceID | Select-Object -First 1)"
        output = subprocess.check_output(["powershell", "-Command", command], shell=True).decode().strip()
        return output if output else None
    except Exception as e:
        print(f"Error: {e}")
        return None


def get_service_details_from_user():  # Prompt user to enter service details (name, username, password).
    service = input(f"\n{WHITE}Enter a {YELLOW}new service name{RESET}: ").strip()
    username = input(f"{WHITE}Enter a {YELLOW}new username{RESET}: ").strip()
    password = input(f"{WHITE}Enter a {YELLOW}new password{RESET}: ").strip()
    timestamp = datetime.now().strftime('%d-%b-%Y')
    return service, username, password, timestamp


def hash_pin(pin, salt):  # Hash the PIN using random key from scrypt.
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


def generate_salt():  # generate a random salt using scrypt.
    salt = os.urandom(16)
    return salt


def generate_key_from_usb_serial():  # Generate a key from the usb controller serial address using PBKDF2 with SHA-256.
    usb_serial = get_usb_controller_device_id()   # getting the usb serial using subprocess library.
    salt = usb_serial.encode()
    kdf = Scrypt(
        salt=salt,
        length=ENCRYPTION_KEY_SIZE,
        n=2 ** 14,
        r=8,
        p=1,
        backend=default_backend()
    )
    filekey = kdf.derive(salt)  # returning the key that will be used to encrypt the mykeycub.bin file
    return filekey


def encrypt_service(service_details, key):  # Encrypt the service details using AES CBC mode.
    iv = os.urandom(16)  # random 16 bit initialisation vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())  # AES cipher using PIN as key.
    encryptor = cipher.encryptor()  # encryptor object created by AES cipher.
    padder = padding.PKCS7(algorithms.AES.block_size).padder()  # padder to match AES block size
    padded_data = padder.update(json.dumps(service_details).encode()) + padder.finalize()  # convert to JSON
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()  # encrypt padded data
    return iv + encrypted_data  # return initialisation vector + encrypted data.


def decrypt_service(encrypted_data, key):  # Decrypt the encrypted service details using AES CBC mode.
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return json.loads(unpadded_data.decode('utf-8'))


def save_to_file(data):  # Save data to a .bin file encrypted with AES using the key derived from USB serial.
    filekey = generate_key_from_usb_serial()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(filekey), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(json.dumps(data).encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    with open(FILE_PATH, 'wb') as file:
        file.write(iv + encrypted_data)


def load_from_file():  # Load data from a .bin file and decrypt using the key derived from USB serial.
    if os.path.exists(FILE_PATH):
        filekey = generate_key_from_usb_serial()
        try:
            with open(FILE_PATH, 'rb') as file:
                encrypted_data = file.read()
            iv = encrypted_data[:16]
            encrypted_data = encrypted_data[16:]
            cipher = Cipher(algorithms.AES(filekey), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
            return json.loads(unpadded_data.decode('utf-8'))
        except Exception as e:
            print(
                f"Exception details: {str(e)}"
                f"{RED}Your KeyCub list has been corrupted, it may have been tampered with.\n"
                f"file key:", filekey,
                f"{WHITE}Would you like to {CYAN}wipe it{WHITE}?{RESET} (yes/no)"
            )
            response = input().strip().lower()
            if response == 'y' or response == 'yes':
                wipe_file()
                print(f"{MAGENTA}\nKeyCub wiped all passwords.{RESET}")
                return None
            else:
                print(f"{WHITE}\nExiting without wiping the corrupt file.{RESET}")
                sys.exit()
    else:
        return None


def print_all_passwords(decrypted_services):  # print all passwords on screen for the user.
    clear_screen()  # clear the screen first
    print(f"\n{WHITE}Saved Passwords{RESET}"
    f"\n{WHITE}----------------{RESET}\n")
    for idx, service in enumerate(decrypted_services, start=1):
        print(
            f"{MAGENTA}{idx}.{WHITE} {service['name']} ({service['timestamp']}){RESET}\n"
            f"   Username: {service['username']}\n"
            f"   Password: {service['password']}\n"
        )


def wipe_file():  # Wipe the entire contents of the .bin file.
    if os.path.exists(FILE_PATH):
        os.remove(FILE_PATH)
        sys.exit()
    else:
        print("No file to wipe.")


def clear_screen():  # Function to clear screen + print logo.
    if os.name == 'nt':  # For Windows
        os.system('cls')
    else:  # For Unix-like systems (Linux, macOS)
        os.system('clear')
    print(f"{MAGENTA}    __ __                  ______            __  ")
    print(f"   / //_/  ___    __  __  / ____/  __  __   / /_ ")
    print(f"{CYAN}  / ,<    / _ \  / / / / / /      / / / /  / __ \ ")
    print(f" / /| |  /  __/ / /_/ / / /___   / /_/ /  / /_/ /")
    print(f"{YELLOW}/_/ |_|  \___/  \__, /  \____/   \__,_/  /_.___/ ")
    print(f"               /____/                                    ")
    print(f"{GREY}Version 1.1 - Niutoh Security 2025 \u00A9{RESET}")


def main():  # main loop.
    # Load existing data from file or initialize empty data
    data = load_from_file() or {'pin_hash': None, 'encrypted_services': None, 'salt': None, 'wrong_attempts': 0}

    # Initialize the wrong attempt counter
    wrong_attempts = data.get('wrong_attempts', 0)

    while True:  # main loop for user inputs.
        clear_screen()
        if 'pin_hash' in data and 'encrypted_services' in data and data['salt']:  # if file exists
            while True:
                pin = get_pin_from_user()  # function for receiving PIN from user.
                salt = urlsafe_b64decode(data['salt'].encode('utf-8'))
                hashed_pin = hash_pin(pin, salt)
                if hashed_pin == urlsafe_b64decode(data['pin_hash'].encode('utf-8')):  # if the PIN is correct...
                    if wrong_attempts > 0:
                        print(f"\nNumber of failed login attempts: {wrong_attempts}")
                    wrong_attempts = 0
                    data['wrong_attempts'] = wrong_attempts  # reset wrong attempt counter upon successful login.
                    save_to_file(data)  # save reset counter to the file.
                    padded_pin = (pin * (ENCRYPTION_KEY_SIZE // len(pin) + 1))[:ENCRYPTION_KEY_SIZE].encode()
                    key = padded_pin  # decrypt all services using the padded pin as the key.
                    encrypted_services = urlsafe_b64decode(data['encrypted_services'].encode('utf-8'))
                    decrypted_services = decrypt_service(encrypted_services, key)
                    print_all_passwords(decrypted_services)  # initial printing of passwords upon login.
                    action_loop(decrypted_services, key, data)  # begin user action loop.
                    break
                else:
                    wrong_attempts += 1  # If wrong PIN is entered, increase wrong attempts ++
                    data['wrong_attempts'] = wrong_attempts
                    save_to_file(data)  # hard save increased wrong attempt counter to file.
                    print(f"{RED}\nWrong PIN. Attempt {wrong_attempts}/{MAX_ATTEMPTS}.{RESET}\n")
                    if wrong_attempts >= MAX_ATTEMPTS:  # if wrong_attempts exceeds limit, wipe the file.
                        print(f"{RED}\nMaximum attempts reached. Wiping the file.\n{RESET}")
                        wipe_file()
                        data = {'pin_hash': None, 'encrypted_services': None, 'salt': None, 'wrong_attempts': 0}
                        save_to_file(data)
                        break

        else:  # if the file does not exist / data corrupted, prompt user to make a new one.
            print(
                f"{YELLOW}\nNo KeyCub file found{WHITE}\n"
                "Create a new KeyCub file by entering a 6-digit PIN.\n"
                f"{RESET}"
            )
            pin = get_pin_from_user()  # get new PIN code from user.
            padded_pin = (pin * (ENCRYPTION_KEY_SIZE // len(pin) + 1))[:ENCRYPTION_KEY_SIZE].encode()
            services = []  # initialise services list.
            salt = generate_salt()  # Hash PIN and encrypt empty services data
            pin_hash = hash_pin(pin, salt)
            key = padded_pin
            encrypted_services = encrypt_service(services, key)

            data['pin_hash'] = urlsafe_b64encode(pin_hash).decode('utf-8')  # new file structure created.
            data['encrypted_services'] = urlsafe_b64encode(encrypted_services).decode('utf-8')
            data['salt'] = urlsafe_b64encode(salt).decode('utf-8')
            data['wrong_attempts'] = 0  # initialising number of wrong attempts to 0
            save_to_file(data)

            while not os.path.exists(FILE_PATH):
                time.sleep(0.1)  # wait until file has been created before continuing with script.

            print(f"{MAGENTA}\nYour KeyCub secure password list has been created.\n{RESET}")  # print when successful
            action_loop(services, key, data)  # enter main user action loop.


def action_loop(decrypted_services, key, data):  # main action loop
    while True:
        if decrypted_services:  # If the decrypted_services list is not empty
            action = input(  # Main action list with all options
                f"{WHITE}\nDo you want to {YELLOW}add{RESET}{WHITE}, {MAGENTA}edit{RESET}{WHITE}, "
                f"{RED}delete{RESET}{WHITE}, {CYAN}wipe{WHITE}, {GREEN}import{WHITE} or {RESET}exit{WHITE}:{RESET} "
            ).strip().lower()
        else:  # If the decrypted_services list is empty
            action = input(  # Limited action list
                f"{WHITE}\nDo you want to {YELLOW}add{RESET}{WHITE}, "
                f"{GREEN}import{WHITE} or {RESET}exit{WHITE}:{RESET} "
            ).strip().lower()
        if action =="debug":
            print("USB device:", get_usb_controller_device_id())
            print("key: ", key)
            print("salt: ", generate_salt())
        if action == "add":  # if user types add.
            service, username, password, timestamp = get_service_details_from_user()
            if not service or not username or not password:
                print(f"{RED}\nService, username and password cannot be blank. Password not saved.{RESET}")
                continue
            decrypted_services.append({  # Add new service to the decrypted services list
                'name': service,
                'username': username,
                'password': password,
                'timestamp': timestamp
            })
            print_all_passwords(decrypted_services)
            print(f"{MAGENTA}\nSaved to KeyCub.\n{RESET}")
        elif action == "edit":  # Edit a service from the list.
            clear_screen()  # printing list when user chooses to edit
            print("\n")
            for idx, service in enumerate(decrypted_services, start=1):
                print(
                    f"{MAGENTA}{idx}.{WHITE} {service['name']} ({service['timestamp']}){RESET}\n"
                    f"   Username: {service['username']}\n"
                    f"   Password: {service['password']}\n"
                )
            try:
                service_number = int(input(
                    f"{WHITE}\nEnter the {MAGENTA}number{WHITE} of the service you wish to edit: {RESET}").strip())
                if service_number < 1 or service_number > len(decrypted_services):  # checking for valid service number
                    raise ValueError
                service = decrypted_services[service_number - 1]  # getting the service via the input service number
                print(  # printing the service to be edited for the user to confirm
                    f"\n{YELLOW}Service to be edited:{WHITE}\n" 
                    f"   {service['name']} ({service['timestamp']}){RESET}\n"
                    f"   Username: {service['username']}\n"
                    f"   Password: {service['password']}\n{RESET}")
                username = input(
                    f"{WHITE}Enter the {YELLOW}updated username{GREY} "
                    f"(leave blank to cancel){WHITE}: {RESET}").strip()
                password = input(
                    f"{WHITE}Enter the {YELLOW}updated password{GREY} "
                    f"(leave blank to cancel){WHITE}: {RESET}").strip()
                if not username or not password:  # cancelling if either password or username is blank.
                    print(f"{RED}\nService, username and password cannot be blank. New password not saved.{RESET}")
                else:
                    service['username'] = username  # updating details in mykeycub.bin file
                    service['password'] = password
                    service['timestamp'] = datetime.now().strftime('%d-%b-%Y')
                    print_all_passwords(decrypted_services)  # printing out all passwords and confirmation message
                    print(f"{MAGENTA}Password updated successfully.{RESET}")
            except ValueError:  # error message if invalid service number entered.
                print(f"{RED}\nPlease enter a valid service number from the list.{RESET}")
        elif action == "delete":  # if delete action is selected.
            clear_screen()  # clear screen and print passwords available to be deleted.
            print(f"\n{WHITE}Saved Passwords{RESET}")
            print(f"{WHITE}----------------{RESET}")
            for idx, service in enumerate(decrypted_services, start=1):
                print(
                    f"{MAGENTA}{idx}.{WHITE} {service['name']} ({service['timestamp']}){RESET}\n"
                    f"   Username: {service['username']}\n"
                    f"   Password: {service['password']}\n"
                )
            try:
                service_number = int(input(  # get number of service to be deleted
                    f"{WHITE}\nEnter the {MAGENTA}number{WHITE} of the service to be deleted: {RESET}").strip())
                if service_number < 1 or service_number > len(decrypted_services):
                    raise ValueError  # error if user's input number is not valid
                service = decrypted_services[service_number - 1]
                print(  # print service to be deleted
                    f"{RED}\nService to be deleted:\n"
                    f"{WHITE} {service['name']} ({service['timestamp']})\n"
                    f"{RESET}   Username: {service['username']}\n"
                    f"   Password: {service['password']}\n"
                    f"{RESET}"
                )
                confirm_delete = input(  # making user confirm service to be deleted
                    f"{RED}Are you sure you want to delete this password?{RESET} (yes/no): ").strip().lower()
                if confirm_delete == 'y' or confirm_delete == 'yes':
                    decrypted_services.pop(service_number - 1)  # deleting selected service.
                    print_all_passwords(decrypted_services)
                    print(f"{MAGENTA}\nPassword deleted successfully.{RESET}")
                else:
                    print(f"{MAGENTA}\nDeletion cancelled.{RESET}")  # deletion cancelled meesage.
            except ValueError:
                print(f"{RED}\nPlease enter in valid service number from the list.{RESET}")
        elif action == "wipe":  # action to wipe / reset the keycub list
            confirm_wipe = input(  # make user confirm wipe
                f"{YELLOW}\nAre you sure you want to wipe the whole password list?{RESET} (yes/no): ").strip().lower()
            if confirm_wipe == 'y' or confirm_wipe == 'yes':
                wipe_file()
                data = {'pin_hash': None, 'encrypted_services': None, 'salt': None, 'wrong_attempts': 0}
                save_to_file(data)  # save wiped data to file
                print(f"{MAGENTA}\nKeyCub wiped all passwords.{RESET}")  # print wipe message
                break
            else:
                print(f"{MAGENTA}\nWipe cancelled.\n{RESET}")  # wipe cancelled (user didnt enter [y]es)
            continue
        elif action == "import":  # action for importing .csv files
            file_path = input(
                f"{WHITE}\nDrag and drop your \"Chrome Passwords.csv\" file here, "
                f"then press enter: {RESET}"
            ).strip()
            file_path = file_path.strip('"')  # Remove quotes from the file path if they exist.
            import_from_csv(file_path, decrypted_services)
        elif action == "exit":  # exiting the script if "exit" is selected.
            print(f"{GREY}\nExiting...\n{RESET}")  # exiting.
            sys.exit()
        else:
            print(f"{RED}\nPlease type out one of the listed actions.{RESET}")  # error if no action is selected.
            continue

        encrypted_services = encrypt_service(decrypted_services, key)  # Encrypt the updated services list
        data['encrypted_services'] = urlsafe_b64encode(encrypted_services).decode('utf-8')   # saved encrypted service.
        save_to_file(data)  # Save updated data to file


if __name__ == "__main__":
    main()
