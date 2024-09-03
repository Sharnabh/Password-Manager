import tkinter as tk
from tkinter import messagebox, simpledialog
import sqlite3
from cryptography.fernet import Fernet
import hashlib
import os

# Key Management
def generate_and_store_key(username):
    """Generate a new key and store it in a file specific to the user, only if it doesn't already exist."""
    key_filename = f'{username}_secret.key'
    if not os.path.exists(key_filename):
        key = Fernet.generate_key()
        with open(key_filename, 'wb') as key_file:
            key_file.write(key)
        print(f"Key generated and stored for {username}.")
    else:
        print(f"Key already exists for {username}. Using the existing key.")

def load_key(username):
    """Load the existing key from the user's key file."""
    key_filename = f'{username}_secret.key'
    return open(key_filename, 'rb').read()

# Encryption and Decryption
def encrypt_data(data, key):
    """Encrypt data using the provided key."""
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(data, key):
    """Decrypt data using the provided key."""
    try:
        fernet = Fernet(key)
        return fernet.decrypt(data.encode()).decode()
    except Exception as e:
        print(f"An error occurred during decryption: {e}")
        return None

# Database setup
def initialize_db():
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        key BLOB NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        service TEXT NOT NULL,
                        username TEXT NOT NULL,
                        password TEXT NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()

initialize_db()

# Hashing with SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Signup and Login functions
def signup(username, password):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    
    hashed_password = hash_password(password)

    # Generate and store the key for this user
    generate_and_store_key(username)
    user_key = load_key(username)

    # Encrypt the hashed password using the key
    encrypted_password = encrypt_data(hashed_password, user_key)

    try:
        cursor.execute("INSERT INTO users (username, password, key) VALUES (?, ?, ?)",
                       (username, encrypted_password, user_key))
        conn.commit()
        messagebox.showinfo("Signup Successful", "You have signed up successfully!")
    except sqlite3.IntegrityError:
        messagebox.showerror("Signup Error", "Username already exists.")
    conn.close()

def login(username, password, window):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    
    hashed_password = hash_password(password)

    # Load the key for this user
    user_key = load_key(username)

    # Encrypt the hashed password to compare with stored encrypted password
    encrypted_password = encrypt_data(hashed_password, user_key)

    cursor.execute("SELECT id, password, key FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        user_id, stored_password, stored_key = user
        # Decrypt stored password to check if it matches the input password's encrypted hash
        decrypted_stored_password = decrypt_data(stored_password, stored_key)
        if decrypted_stored_password == hashed_password:
            messagebox.showinfo("Login Successful", "You have logged in successfully!")
            window.destroy()  # Close the login/signup window
            open_password_manager(user_id, user_key, username)
        else:
            messagebox.showerror("Login Error", "Incorrect password.")
    else:
        messagebox.showerror("Login Error", "Username not found.")

# Password Manager Functions
def open_password_manager(user_id, user_key, username):
    PasswordManagerWindow(user_id, user_key, username)

def add_password(user_id, service, username, password, user_key):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()

    # Encrypt the username and password using the user's key
    encrypted_username = encrypt_data(username, user_key)
    encrypted_password = encrypt_data(password, user_key)

    cursor.execute("INSERT INTO passwords (user_id, service, username, password) VALUES (?, ?, ?, ?)",
                   (user_id, service, encrypted_username, encrypted_password))
    conn.commit()
    conn.close()
    messagebox.showinfo("Success", "Password added successfully.")

def retrieve_passwords(user_id, user_key):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, service, username, password FROM passwords WHERE user_id = ?", (user_id,))
    passwords = cursor.fetchall()
    conn.close()

    decrypted_passwords = []
    for password_id, service, encrypted_username, encrypted_password in passwords:
        decrypted_username = decrypt_data(encrypted_username, user_key)
        decrypted_password = decrypt_data(encrypted_password, user_key)
        decrypted_passwords.append((password_id, service, decrypted_username, decrypted_password))

    return decrypted_passwords

def delete_passwords(user_id, ids_to_delete):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()
    cursor.executemany("DELETE FROM passwords WHERE user_id = ? AND id = ?", [(user_id, i) for i in ids_to_delete])
    conn.commit()
    conn.close()
    messagebox.showinfo("Success", "Selected passwords deleted successfully.")

def update_password(user_id, password_id, new_password, user_key):
    conn = sqlite3.connect('password_manager.db')
    cursor = conn.cursor()

    # Encrypt the new password using the user's key
    encrypted_password = encrypt_data(new_password, user_key)

    cursor.execute("UPDATE passwords SET password = ? WHERE user_id = ? AND id = ?",
                   (encrypted_password, user_id, password_id))
    conn.commit()
    conn.close()
    messagebox.showinfo("Success", "Password updated successfully.")

# GUI Components
class PasswordManagerWindow:
    def __init__(self, user_id, user_key, username):
        self.user_id = user_id
        self.user_key = user_key
        self.username = username
        self.window = tk.Tk()
        self.window.title("Password Manager")
        tk.Label(self.window, text="Service").grid(row=0, column=0)
        tk.Label(self.window, text="Username").grid(row=0, column=1)
        tk.Label(self.window, text="Password").grid(row=0, column=2)

        self.service_entry = tk.Entry(self.window)
        self.service_entry.grid(row=1, column=0)
        self.username_entry = tk.Entry(self.window)
        self.username_entry.grid(row=1, column=1)
        self.password_entry = tk.Entry(self.window)
        self.password_entry.grid(row=1, column=2)

        tk.Button(self.window, text="Add Password", command=self.add_password).grid(row=2, column=0, columnspan=3)
        tk.Button(self.window, text="View Passwords", command=self.request_master_password).grid(row=3, column=0, columnspan=3)
        tk.Button(self.window, text="Delete Passwords", command=self.delete_passwords).grid(row=4, column=0, columnspan=3)
        tk.Button(self.window, text="Update Password", command=self.update_password).grid(row=5, column=0, columnspan=3)
        tk.Button(self.window, text="Logout", command=self.logout).grid(row=6, column=0, columnspan=3)

        self.passwords_frame = tk.Frame(self.window)
        self.passwords_frame.grid(row=7, column=0, columnspan=3)

        self.window.mainloop()

    def add_password(self):
        service = self.service_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        add_password(self.user_id, service, username, password, self.user_key)

    def request_master_password(self):
        # Prompt the user to enter the master password
        master_password = simpledialog.askstring("Master Password", "Enter your master password:", show='*')
        if master_password:
            self.verify_master_password(master_password)

    def verify_master_password(self, master_password):
        conn = sqlite3.connect('password_manager.db')
        cursor = conn.cursor()
        cursor.execute("SELECT password, key FROM users WHERE id = ?", (self.user_id,))
        user = cursor.fetchone()
        conn.close()

        if user:
            stored_password, stored_key = user
            hashed_master_password = hash_password(master_password)
            decrypted_stored_password = decrypt_data(stored_password, stored_key)

            if decrypted_stored_password == hashed_master_password:
                self.view_passwords()
            else:
                messagebox.showerror("Error", "Incorrect master password.")
        else:
            messagebox.showerror("Error", "User not found.")

    def view_passwords(self):
        for widget in self.passwords_frame.winfo_children():
            widget.destroy()

        tk.Label(self.passwords_frame, text="Service").grid(row=0, column=0)
        tk.Label(self.passwords_frame, text="Username").grid(row=0, column=1)
        tk.Label(self.passwords_frame, text="Password").grid(row=0, column=2)

        passwords = retrieve_passwords(self.user_id, self.user_key)
        for idx, (password_id, service, username, password) in enumerate(passwords):
            tk.Label(self.passwords_frame, text=service).grid(row=idx+1, column=0)
            tk.Label(self.passwords_frame, text=username).grid(row=idx+1, column=1)
            tk.Label(self.passwords_frame, text=password).grid(row=idx+1, column=2)

    def delete_passwords(self):
        self.delete_window = tk.Toplevel(self.window)
        self.delete_window.title("Delete Passwords")

        tk.Label(self.delete_window, text="Select Passwords to Delete").grid(row=0, column=0)

        self.checkboxes = []
        self.password_ids = []

        passwords = retrieve_passwords(self.user_id, self.user_key)
        for idx, (password_id, service, _, _) in enumerate(passwords):
            var = tk.BooleanVar()
            self.checkboxes.append(var)
            self.password_ids.append(password_id)
            tk.Checkbutton(self.delete_window, text=service, variable=var).grid(row=idx+1, column=0)

        tk.Button(self.delete_window, text="Delete Selected", command=self.confirm_delete).grid(row=len(passwords)+1, column=0)

    def confirm_delete(self):
        ids_to_delete = [self.password_ids[idx] for idx, var in enumerate(self.checkboxes) if var.get()]
        if ids_to_delete:
            delete_passwords(self.user_id, ids_to_delete)
            self.delete_window.destroy()
            self.view_passwords()  # Refresh the view
        else:
            messagebox.showwarning("Warning", "No passwords selected for deletion.")

    def update_password(self):
        self.update_window = tk.Toplevel(self.window)
        self.update_window.title("Update Password")

        tk.Label(self.update_window, text="Select Service").grid(row=0, column=0)
        self.service_listbox = tk.Listbox(self.update_window)
        self.service_listbox.grid(row=1, column=0)

        passwords = retrieve_passwords(self.user_id, self.user_key)
        self.password_map = {}

        for idx, (password_id, service, _, _) in enumerate(passwords):
            self.service_listbox.insert(idx, service)
            self.password_map[idx] = password_id

        tk.Label(self.update_window, text="New Password").grid(row=2, column=0)
        self.new_password_entry = tk.Entry(self.update_window)
        self.new_password_entry.grid(row=3, column=0)

        tk.Button(self.update_window, text="Update", command=self.confirm_update).grid(row=4, column=0)

    def confirm_update(self):
        selected_idx = self.service_listbox.curselection()
        if selected_idx:
            password_id = self.password_map[selected_idx[0]]
            new_password = self.new_password_entry.get()
            update_password(self.user_id, password_id, new_password, self.user_key)
            self.update_window.destroy()
        else:
            messagebox.showwarning("Warning", "No service selected for update.")

    def logout(self):
        self.window.destroy()
        LoginSignupWindow()

class LoginSignupWindow:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Login / Signup")

        tk.Label(self.window, text="Username").grid(row=0, column=0)
        tk.Label(self.window, text="Password").grid(row=1, column=0)
        self.username_entry = tk.Entry(self.window)
        self.username_entry.grid(row=0, column=1)
        self.password_entry = tk.Entry(self.window, show='*')
        self.password_entry.grid(row=1, column=1)

        tk.Button(self.window, text="Login", command=self.login).grid(row=2, column=0, columnspan=2)
        tk.Button(self.window, text="Signup", command=self.signup).grid(row=3, column=0, columnspan=2)

        self.window.mainloop()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        login(username, password, self.window)

    def signup(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        signup(username, password)

# Start the application
LoginSignupWindow()
