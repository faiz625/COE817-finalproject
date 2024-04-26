import socket
import threading
from keys import derive_keys, aes_decrypt, verify_hmac, encrypt_audit_log_entry, generate_hmac, generate_rsa_keys
import hashlib
import datetime
import Crypto.PublicKey.RSA as RSA
from Crypto.Random import get_random_bytes

pre_shared_key = b"sharedkey321"
registered_users = {}

public_key, private_key = generate_rsa_keys()

# Save the public key
with open("public_key.pem", "wb") as pk_file:
    pk_file.write(public_key)

# Save the private key securely as well
with open("private_key.pem", "wb") as pk_file:
    pk_file.write(private_key)
    
class Server:
    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(('localhost', 5555))
        self.server.listen(5)
        self.public_key, self.private_key = generate_rsa_keys()

    def generate_master_secret(self, shared_info):
        master_secret = pre_shared_key + shared_info.encode()
        return hashlib.sha256(master_secret).hexdigest()

    def handle_registration(self, connection, username, password):
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        # Register the user
        if username not in registered_users:
            registered_users[username] = (password_hash, 0)
            connection.send("Registration successful. Proceed with login.".encode())
        else:
            connection.send("Already registered.".encode())

    def handle_login(self, connection, username, password):
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        # Validate login attempt
        if username in registered_users and registered_users[username][0] == password_hash:
            connection.send("Login successful. Generating Master Secret.".encode())
            # run authenticated key distribution protocol
            self.distribute_keys(connection, username)
        else:
            connection.send("User not registered.".encode())

    def authenticate_client(self, connection, master_secret):
        print("verifying client...")
        # generate nonce
        server_nonce = get_random_bytes(16)
        # send server nonce to client
        connection.send(server_nonce)
        # receive nonces
        client_nonce = connection.recv(16)

        # authentication
        concatenated = client_nonce + b":" + server_nonce + b":" + pre_shared_key
        # create hash
        hashed_concatenated = hashlib.sha256(concatenated).hexdigest()
        # send hash to client
        connection.send(hashed_concatenated.encode())
        # receive hash from client
        client_hash = connection.recv(1024).decode()
        if client_hash == hashed_concatenated:
            auth_result = "success"
        else:
            auth_result = "fail"

        return auth_result

    def distribute_keys(self, connection, username):
        shared_info = "session_info_" + username
        master_secret = self.generate_master_secret(shared_info)

        # Authenticate client to server
        auth_result = self.authenticate_client(connection, master_secret)

        if auth_result == "success":
            # Send the Master Secret to the client
            connection.send(master_secret.encode())
            print(f"sent master secret: {master_secret}")

            # Derive two keys: data encryption key and MAC key from the Master Secret
            encryption_key_bytes, mac_key_bytes = derive_keys(master_secret)
            print(f"encryption key: {encryption_key_bytes}")
            print(f"MAC key: {mac_key_bytes}")

            # Receive encrypted data and MAC from the client
            encrypted_data_with_mac = connection.recv(2048)
            encrypted_data = encrypted_data_with_mac[:-32]  # Assuming the last 32 bytes are the MAC
            received_mac = encrypted_data_with_mac[-32:]

            # Decrypt the encrypted data to get the plaintext for HMAC verification
            print("water")
            print(encrypted_data)
            transaction_data_plaintext = aes_decrypt(encrypted_data, encryption_key_bytes)

            # Now, generate HMAC for the decrypted plaintext for verification
            generated_mac_for_debug = generate_hmac(transaction_data_plaintext, mac_key_bytes)

            print(f"Generated HMAC for debug: {generated_mac_for_debug.hex()}")
            print(f"Received HMAC: {received_mac.hex()}")

            if verify_hmac(transaction_data_plaintext, mac_key_bytes, received_mac):
                # HMAC verification successful
                action, _, amount = transaction_data_plaintext.decode().partition(':')
                self.process_transaction(username, action, amount)
                self.log_transaction(username, action)
            else:
                print("MAC verification failed.")
                
    def handle_client(self, connection):
        while True:
            # Attempt to receive a command, assuming it's text-based
            data = connection.recv(1024)  # Receive data as bytes
            print("Data")
            print(data)

            # Check if the data can be decoded as UTF-8 text
            try:
                if len(data) > 16:
                    data = data[:-32]
                    shared_info = "session_info_" + "wa"
                    master_secret = self.generate_master_secret(shared_info)
                    encryption_key_bytes, mac_key_bytes = derive_keys(master_secret)
                    data = aes_decrypt(data, encryption_key_bytes)
                    print(data)

                print("air")
                print(data)
                client_command = data.decode('utf-8')
                # Assuming successful decoding, proceed with text-based logic
                username, password, client_command = client_command.split(":")
                print(client_command)

                if client_command in ["register", "login", "deposit", "withdraw", "retrieve balance"]:
                    if client_command == "register":
                        self.handle_registration(connection, username, password)

                    elif client_command == "login":
                        self.handle_login(connection, username, password)
                    
                    elif client_command == "deposit":
                        self.logBankTransaction(username, client_command, password)
                    
                    elif client_command == "withdraw":
                        self.logBankTransaction(username, client_command, password)

                    elif client_command == "retrieve balance":
                        self.getBalance(username, client_command)
                    

            except UnicodeDecodeError:
                # Handle binary data or other non-text data
                # Since your current logic doesn't explicitly handle binary data here,
                # you might simply pass or log a message for now
                print("Received binary or non-UTF-8 data, which is not handled explicitly here.")

    def process_transaction(self, user_id, action, amount=""):
        # Placeholder for processing logic
        print(f"Processing {action} for {user_id}. Amount: {amount}")
    
    def getBalance(self, user_id, action):
        amount = 0
        if user_id == "la":
            amount = 300
        else:
            amount = 100
        print(f"Retrieved balance for {user_id}. Current balance is {amount}")

    def logBankTransaction(self, user_id, action, amount):
        print(f"Processing {action} for {user_id}. Amount: {amount}")
        log_entry = f"{user_id} | {action} | {amount} | {datetime.datetime.now()}"
        encrypted_log_entry = encrypt_audit_log_entry(self.public_key, log_entry)
        with open("encrypted_audit_log.txt", "a") as log_file:
            log_file.write(encrypted_log_entry + '\n')


    def log_transaction(self, user_id, action):
        # Example log entry
        print(f"Logging Transaction for {user_id} Amount:")
        log_entry = f"{user_id} | {action} | {datetime.datetime.now()}"
        encrypted_log_entry = encrypt_audit_log_entry(self.public_key, log_entry)
        with open("encrypted_audit_log.txt", "a") as log_file:
            log_file.write(encrypted_log_entry + '\n')

    def start_server(self):
        print("Server listening on localhost:5555")
        while True:
            conn, addr = self.server.accept()
            thread = threading.Thread(target=self.handle_client, args=(conn,))
            print(f"Connection from {addr} has been established.")
            thread.start()


if __name__ == "__main__":
    s = Server()
    s.start_server()
