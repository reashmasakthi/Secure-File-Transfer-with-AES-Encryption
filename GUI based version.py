import os
import threading
import bluetooth
from tkinter import Tk, Label, Button, Entry, filedialog, Text, END
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from hashlib import pbkdf2_hmac

# AES Key Derivation from Password
def derive_key(password):
    salt = b'static_salt'  # In production, use a random salt per user/session
    return pbkdf2_hmac('sha256', password.encode(), salt, 100000, 32)

# AES Encryption
def encrypt_file(file_path, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    with open(file_path, 'rb') as f:
        data = f.read()

    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_path = file_path + '.enc'
    with open(encrypted_path, 'wb') as f:
        f.write(iv + encrypted_data)

    return encrypted_path

# AES Decryption
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

# Scan Bluetooth Devices
def scan_devices(status_box):
    status_box.insert(END, "Scanning for Bluetooth devices...\n")
    devices = bluetooth.discover_devices(duration=8, lookup_names=True)
    if not devices:
        status_box.insert(END, "No devices found.\n")
    else:
        status_box.insert(END, "Devices found:\n")
        for addr, name in devices:
            status_box.insert(END, f"{name} - {addr}\n")
    return devices

# File Sending via Bluetooth
def send_file_via_bluetooth(file_path, target_address, status_box):
    port = 3
    with bluetooth.BluetoothSocket(bluetooth.RFCOMM) as sock:
        sock.connect((target_address, port))
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            while chunk:
                sock.send(chunk)
                chunk = f.read(1024)
    status_box.insert(END, f"File sent to {target_address}\n")

# File Receiving via Bluetooth
def receive_file_via_bluetooth(output_path, key, status_box):
    port = 3
    with bluetooth.BluetoothSocket(bluetooth.RFCOMM) as sock:
        sock.bind(("", port))
        sock.listen(1)
        status_box.insert(END, f"Waiting for connection on port {port}...\n")
        client_sock, client_info = sock.accept()
        with client_sock, open(output_path, 'wb') as f:
            status_box.insert(END, f"Connected to {client_info}\n")
            while True:
                data = client_sock.recv(1024)
                if not data:
                    break
                f.write(data)
        status_box.insert(END, f"File received and saved as {output_path}\n")

    decrypted_path = decrypt_file(output_path, key)
    status_box.insert(END, f"File decrypted and saved as {decrypted_path}\n")

# GUI Application
class SecureFileSharingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Bluetooth File Sharing System")
        self.file_path = None

        Label(root, text="Password:").pack()
        self.password_entry = Entry(root, show="*")
        self.password_entry.pack()

        Button(root, text="Scan Devices", command=self.scan_devices).pack()
        Button(root, text="Send File", command=self.send_file).pack()
        Button(root, text="Receive File", command=self.receive_file).pack()

        self.status_box = Text(root, height=15, width=60)
        self.status_box.pack()

        self.devices = []

    def scan_devices(self):
        self.devices = scan_devices(self.status_box)

    def send_file(self):
        if not self.devices:
            self.status_box.insert(END, "Please scan devices first!\n")
            return

        self.file_path = filedialog.askopenfilename()
        self.status_box.insert(END, f"Selected file: {self.file_path}\n")

        password = self.password_entry.get()
        key = derive_key(password)
        encrypted_path = encrypt_file(self.file_path, key)

        # For simplicity, sending to the first detected device
        if self.devices:
            target_address = self.devices[0][0]
            threading.Thread(target=send_file_via_bluetooth, args=(encrypted_path, target_address, self.status_box)).start()
        else:
            self.status_box.insert(END, "No devices available to send the file.\n")

    def receive_file(self):
        password = self.password_entry.get()
        key = derive_key(password)
        output_path = 'received_file.enc'
        threading.Thread(target=receive_file_via_bluetooth, args=(output_path, key, self.status_box)).start()

if __name__ == '__main__':
    root = Tk()
    app = SecureFileSharingApp(root)
    root.mainloop()
