import socket
from keys import derive_keys, aes_encrypt, generate_hmac, aes_decrypt
import tkinter as tk
from tkinter import messagebox
import hashlib
from Crypto.Random import get_random_bytes

pre_shared_key = b"sharedkey321"
class Client:
    globalUsername = "wa"
    def __init__(self):
        # Create a socket and connect to the server
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect(('localhost', 5555))

    def start_client(self):
        self.window = tk.Tk()
        self.window.title("ATM Client")
        self.window.geometry("300x200")

        # Create and place labels and entry fields
        username_label = tk.Label(self.window, text="Username:")
        username_label.pack()
        self.username_entry = tk.Entry(self.window)
        self.username_entry.pack()

        password_label = tk.Label(self.window, text="Password:")
        password_label.pack()
        self.password_entry = tk.Entry(self.window, show="*")
        self.password_entry.pack()

        self.register_button = tk.Button(self.window, text="Register", command=self.register_client)
        self.register_button.pack()

        self.login_button = tk.Button(self.window, text="Login", command=self.login_client)
        self.login_button.pack()

        self.window.mainloop()

    def register_client(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        action = "register"

        if username == "" or password == "":
            messagebox.showerror("Error", "Please fill all fields.")
        else:
            # send creds over to the server
            credentials = f"{username}:{password}:{action}"
            self.client.send(credentials.encode())
            self.verify_creds()

    def login_client(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        action = "login"

        global globalUsername
        globalUsername = username

        if username == "" or password == "":
            messagebox.showerror("Error", "Please fill all fields.")
        else:
            # send creds over to the server
            credentials = f"{username}:{password}:{action}"
            self.client.send(credentials.encode())
            self.verify_creds()

    def authenticate_server(self):
        # generate nonce
        client_nonce = get_random_bytes(16)
        # receive server nonce
        server_nonce = self.client.recv(16)
        # send client nonce to server
        self.client.send(client_nonce)
        # receive hash from server
        server_hash = self.client.recv(1024).decode()

        # authentication
        concatenated = client_nonce + b":" + server_nonce + b":" + pre_shared_key
        # create hash
        client_hash = hashlib.sha256(concatenated).hexdigest()
        # send hash to server
        self.client.send(client_hash.encode())

        if client_hash == server_hash:
            auth_result = "success"
        else:
            auth_result = "fail"

        return auth_result

    def derive_keys(self):
        # Handle Master Secret acknowledgment
        master_secret = self.client.recv(1024).decode()
        print(f"Received master secret: {master_secret}")

        # Derive encryption and MAC keys from the Master Secret
        encryption_key, mac_key = derive_keys(master_secret)
        print(f"encryption key: {encryption_key}")
        print(f"MAC key: {mac_key}")
        return encryption_key, mac_key

    def do_transactions(self):
        # create new window when logged in
        self.window.destroy()
        self.menu = tk.Tk()
        self.menu.title("ATM Client")
        self.menu.geometry("300x200")
        menu_label = tk.Label(self.menu, text="Welcome to ATM")
        menu_label.pack()

        deposit_label = tk.Label(self.menu, text="Deposit:")
        deposit_label.pack()
        self.deposit_entry = tk.Entry(self.menu)
        self.deposit_entry.pack()

        self.deposit_button = tk.Button(self.menu, text="Deposit", command=self.deposit)
        self.deposit_button.pack()

        withdraw_label = tk.Label(self.menu, text="Withdraw:")
        withdraw_label.pack()
        self.withdraw_entry = tk.Entry(self.menu)
        self.withdraw_entry.pack()

        self.withdraw_button = tk.Button(self.menu, text="Withdraw", command=self.withdraw)
        self.withdraw_button.pack()

        bal_label = tk.Label(self.menu, text="Balance Inquiry:")
        bal_label.pack()

        self.bal_button = tk.Button(self.menu, text="Balance Inquiry", command=self.balance_inquiry)
        self.bal_button.pack()

        self.menu.mainloop()

    def deposit(self):
        amount = self.deposit_entry.get()
        action = "deposit"
        transaction_data = globalUsername + ":" + amount + ":" + action
        # Encrypt the transaction data
        encrypted_data = aes_encrypt(transaction_data.encode(), self.encryption_key_bytes)
        decrypted_data = aes_decrypt(encrypted_data, self.encryption_key_bytes)
        print("Decrypted Data")
        print(self)
        print(self.encryption_key_bytes)
        print(encrypted_data)
        print(decrypted_data)

        # Generate MAC for the transaction data
        mac = generate_hmac(transaction_data.encode(), self.mac_key_bytes)
        # Combine encrypted data and MAC, then send to server
        self.client.send(encrypted_data + mac)
    def withdraw(self):
        amount = self.withdraw_entry.get()
        action = "withdraw"
        transaction_data = globalUsername + ":" + amount + ":" + action
        # Encrypt the transaction data
        encrypted_data = aes_encrypt(transaction_data.encode(), self.encryption_key_bytes)
        decrypted_data = aes_decrypt(encrypted_data, self.encryption_key_bytes)
        print("Decrypted Data")
        print(self)
        print(self.encryption_key_bytes)
        print(encrypted_data)
        print(decrypted_data)

        # Generate MAC for the transaction data
        mac = generate_hmac(transaction_data.encode(), self.mac_key_bytes)
        # Combine encrypted data and MAC, then send to server
        self.client.send(encrypted_data + mac)

    def balance_inquiry(self):
        action = "retrieve balance"
        transaction_data = globalUsername + ":" + "0" + ":" + action
        # Encrypt the transaction data
        encrypted_data = aes_encrypt(transaction_data.encode(), self.encryption_key_bytes)
        decrypted_data = aes_decrypt(encrypted_data, self.encryption_key_bytes)
        print("Decrypted Data")
        print(self)
        print(self.encryption_key_bytes)
        print(encrypted_data)
        print(decrypted_data)

        # Generate MAC for the transaction data
        mac = generate_hmac(transaction_data.encode(), self.mac_key_bytes)
        # Combine encrypted data and MAC, then send to server
        self.client.send(encrypted_data + mac)
        
    def verify_creds(self):
        # Receive server response (registration success or login status)
        response = self.client.recv(1024).decode()
        print(f"Server response: {response}")

        if "Login successful" in response:
            messagebox.showinfo("Success", "Successful Login.")

            # authenticate server to client
            auth_result = self.authenticate_server()
            print(auth_result)
            if auth_result == "success":
                encryption_key, mac_key = self.derive_keys()
                self.encryption_key_bytes = bytes.fromhex(encryption_key) if isinstance(encryption_key, str) else encryption_key
                self.mac_key_bytes = bytes.fromhex(mac_key) if isinstance(mac_key, str) else mac_key
                print(f"Client-side Encryption Key: {self.encryption_key_bytes}")
                print(f"Client-side MAC Key: {self.mac_key_bytes}")

                # User action selection
                self.do_transactions()
            else:
                messagebox.showerror("Error", "Authentication Failed.")
        elif "User not registered" in response:
            messagebox.showerror("Error", "User not found, please register.")
        elif "Already registered" in response:
            messagebox.showerror("Error", "Account already registered, please login.")
        else:
            messagebox.showinfo("Success", "Successful Registration.")

if __name__ == "__main__":
    c = Client()
    c.start_client()

