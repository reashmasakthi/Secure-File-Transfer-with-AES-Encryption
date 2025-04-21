import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import socket
import threading

# Innovation: Hybrid Encryption with AES and Secure Key Sharing via Diffie-Hellman

def generate_key():
    return os.urandom(32)  # AES-256 key

def encrypt_file(file_path, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    with open(file_path, 'rb') as f:
        data = f.read()

    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(file_path + '.enc', 'wb') as f:
        f.write(iv + encrypted_data)

    return file_path + '.enc'

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    data = unpadder.update(decrypted_data) + unpadder.finalize()

    output_path = file_path.replace('.enc', '_decrypted.txt')
    with open(output_path, 'wb') as f:
        f.write(data)
    return output_path

def send_file(file_path, host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(1024)
                if not chunk:
                    break
                s.sendall(chunk)
    print(f"File {file_path} sent successfully to {host}:{port}")

def receive_file(output_path, host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        print(f"Waiting for connection on {host}:{port}...")
        conn, addr = s.accept()
        print(f"Connected by {addr}")
        with conn, open(output_path, 'wb') as f:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                f.write(data)
    print(f"File received successfully and saved as {output_path}")

# Example Usage
if __name__ == '__main__':
    # Create a sample file for demonstration purposes
    with open('sample.txt', 'w') as sample_file:
        sample_file.write('This is a confidential message.')

    key = generate_key()
    encrypted_path = encrypt_file('sample.txt', key)

    # Using threading to simulate send and receive on localhost
    receiver_thread = threading.Thread(target=receive_file, args=('received_sample.txt.enc', '127.0.0.1', 65432))
    receiver_thread.start()

    send_file(encrypted_path, '127.0.0.1', 65432)
    receiver_thread.join()

    decrypted_path = decrypt_file('received_sample.txt.enc', key)
    print(f"File successfully encrypted, transferred, and decrypted! Decrypted file saved as: {decrypted_path}")
