# kissa zahra     i210572       Information security A2, Q2, serve

import socket
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

CREDENTIALS_FILE = "creds.txt"
P = 23  # Prime number
G = 5   # Primitive root modulo P

# Function to decrypt AES-128-CBC
def decrypt_aes_cbc(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

# Function to hash password
def hash_password(password, salt):
    salted_password = password + salt
    return hashlib.sha256(salted_password.encode()).hexdigest()

# Function to save credentials
def save_credentials(email, username, password_hash, salt):
    with open(CREDENTIALS_FILE, "a") as f:
        f.write(f"email: {email}, username: {username}, password: {password_hash}, salt: {salt}\n")

# Check if username exists
def get_user_credentials(username):
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as f:
            for line in f.readlines():
                if f"username: {username}" in line:
                    parts = line.strip().split(", ")
                    return parts[2].split(": ")[1], parts[3].split(": ")[1]
    return None, None

# Function to encrypt AES-128-CBC
def encrypt_aes_cbc(key, iv, data):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

# Server setup
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost', 5000))
server.listen(1)
print("Server is listening on port 5000...")

while True:
    client_socket, client_address = server.accept()
    print(f"Connection established with {client_address}")

    # Diffie-Hellman Key Exchange
    private_key = 7
    A = pow(G, private_key, P)
    client_socket.send(str(A).encode())
    B = int(client_socket.recv(1024).decode())
    shared_key = pow(B, private_key, P)

    option = client_socket.recv(1024).decode()

    if option == "register":
        iv = client_socket.recv(16)
        encrypted_data = client_socket.recv(1024)
        decrypted_data = decrypt_aes_cbc(shared_key.to_bytes(16, 'big'), iv, encrypted_data)
        email, username, password = decrypted_data.decode().split(",")
        if not get_user_credentials(username)[0]:
            salt = os.urandom(4).hex()
            password_hash = hash_password(password, salt)
            save_credentials(email, username, password_hash, salt)
            client_socket.send("Registration successful.".encode())
        else:
            client_socket.send("Username already exists.".encode())

    elif option == "login":
        iv = client_socket.recv(16)
        encrypted_data = client_socket.recv(1024)
        decrypted_data = decrypt_aes_cbc(shared_key.to_bytes(16, 'big'), iv, encrypted_data)
        username, password = decrypted_data.decode().split(",")
        stored_hash, salt = get_user_credentials(username)
        if stored_hash:
            password_hash = hash_password(password, salt)
            if password_hash == stored_hash:
                client_socket.send("Login successful.".encode())
            else:
                client_socket.send("Incorrect password.".encode())
        else:
            client_socket.send("Username not found.".encode())

    # Chat loop (Only occurs if login/registration is successful)
    else:
        client_socket.close()
        continue

    while True:
        encrypted_message = client_socket.recv(1024)
        iv = encrypted_message[:16]  
        encrypted_chat_message = encrypted_message[16:]

        # Decrypt the message
        decrypted_message = decrypt_aes_cbc(shared_key.to_bytes(16, 'big'), iv, encrypted_chat_message)  #using aes encryption
        print(f"Client: {decrypted_message.decode()}")

        # If the client sends "bye", terminate the connection
        if decrypted_message.decode().lower() == "bye":
            print("Client: bye. Closing connection.")
            client_socket.send(iv + encrypt_aes_cbc(shared_key.to_bytes(16, 'big'), iv, b"bye"))
            break

        server_message = input("Server: ")

        # If the server types "bye", terminate the connection
        if server_message.lower() == "bye":
            client_socket.send(iv + encrypt_aes_cbc(shared_key.to_bytes(16, 'big'), iv, b"bye"))
            break

        # Encrypt the server's response
        iv = os.urandom(16)
        encrypted_response = encrypt_aes_cbc(shared_key.to_bytes(16, 'big'), iv, server_message.encode())
        client_socket.send(iv + encrypted_response)

    client_socket.close()

