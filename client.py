# kissa zahra     i210572       Information security A2, Q2, client
import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

P = 23
G = 5

# Function to encrypt AES-128-CBC
def encrypt_aes_cbc(key, iv, data):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt_aes_cbc(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost', 5000))

private_key = 3
B = pow(G, private_key, P)
A = int(client.recv(1024).decode())
client.send(str(B).encode())
shared_key = pow(A, private_key, P)

# User chooses to register or login
option = input("Enter 'register' to register or 'login' to login: ")
client.send(option.encode())

if option == "register":
    email = input("Enter email: ")
    username = input("Enter username: ")
    password = input("Enter password: ")
    data = f"{email},{username},{password}".encode()

elif option == "login":
    username = input("Enter username: ")
    password = input("Enter password: ")
    data = f"{username},{password}".encode()

# Encrypt data and send to server
iv = os.urandom(16)
encrypted_data = encrypt_aes_cbc(shared_key.to_bytes(16, 'big'), iv, data)

client.send(iv)
client.send(encrypted_data)

# Server Response
response = client.recv(1024).decode()
print(response)

if "successful" not in response:  # If login or registration is not successful, close the connection
    client.close()
    exit()

# Chat loop (Only occurs if login/registration is successful)
while True:
    message = input("You: ")
    
    # If the user types "bye", terminate the connection
    if message.lower() == "bye":
        iv = os.urandom(16)
        encrypted_message = encrypt_aes_cbc(shared_key.to_bytes(16, 'big'), iv, message.encode())  #using aes encryption
        client.send(iv + encrypted_message)
        break  # Exit the loop

    # Encrypt and send message
    iv = os.urandom(16)
    encrypted_message = encrypt_aes_cbc(shared_key.to_bytes(16, 'big'), iv, message.encode())
    client.send(iv + encrypted_message)

    # Receive and decrypt server response
    encrypted_response = client.recv(1024)
    iv = encrypted_response[:16]
    encrypted_chat_message = encrypted_response[16:]
    decrypted_message = decrypt_aes_cbc(shared_key.to_bytes(16, 'big'), iv, encrypted_chat_message)
    
    if decrypted_message.decode().lower() == "bye":
        print("Server: bye. Closing connection.")
        break  # Exit the loop

    print("Server:", decrypted_message.decode())

client.close()
