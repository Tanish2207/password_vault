import os
import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
from cryptography.fernet import Fernet

class VaultBackend:
    def __init__(self):
        self.key = None
        self.password_file = None
        self.pwd_dict = {}

    def create_key(self, key_path):
        self.key = Fernet.generate_key()
        print(self.key)
        self.cipher_suite = Fernet(self.key)
        with open(key_path, 'wb') as f:
            f.write(self.key)
    
    def load_existing_key(self, key_path):
        with open(key_path, 'rb') as f:
            self.key = f.read()
            print(self.key)
        self.cipher_suite = Fernet(self.key)

    def create_pwd_file(self, pwd_path, initial_values=None):
        self.password_file = pwd_path
        print(self.password_file)

        if initial_values is not None:
            for key, value in initial_values.items():
                self.add_pwd(key, value)
    
    def load_pwd_file(self, pwd_path):
        self.password_file = pwd_path
        with open(pwd_path, 'r') as f:
            for line in f:
                site, encrypted = line.split(":")
                self.pwd_dict[site] = self.cipher_suite.decrypt(encrypted.encode()).decode()

    def add_pwd(self, site, password, pwd_path):
        self.password_file = pwd_path
        self.pwd_dict[site] = password

        if self.password_file is not None:
            with open(self.password_file, 'a+') as f:
                encrypted = self.cipher_suite.encrypt(password.encode())
                f.write(site + ":" + encrypted.decode() + "\n")
        else:
            with open(self.password_file, 'w') as f:
                encrypted = self.cipher_suite.encrypt(password.encode())
                f.write(site + ":" + encrypted.decode() + "\n")

    def get_pwd(self, site):
        return self.pwd_dict[site]
    
class PasswordManagerApp(VaultBackend):
    def __init__(self, root, username):
        super().__init__()
        self.root = root
        self.root.title("1Password - Password Manager")
        self.root.geometry("600x400")
        self.root.configure(bg="#252420")
        self.load_existing_key("finalkeys.key")

        # Header
        self.header_label = tk.Label(root, text="1Password", bg="#252420", fg="white", font=("Arial", 16, "bold"))
        self.header_label.pack(pady=10)

        # Welcome Message
        self.welcome_label = tk.Label(
            root,
            text=f"Welcome back, {username}!",
            bg="#252420",
            fg="white",
            font=("Arial", 14)
        )
        self.welcome_label.pack(pady=5)

        # Password List
        self.password_list_frame = tk.Frame(root, bg="#252420")
        self.password_list_frame.pack(pady=10)

        self.password_list_label = tk.Label(
            self.password_list_frame,
            text="List of my passwords",
            bg="#252420",
            fg="white",
            font=("Arial", 12, "bold")
        )
        self.password_list_label.grid(row=0, column=0, sticky="w")

        self.add_password_button = tk.Button(
            self.password_list_frame,
            text="Add a new password",
            command=self.add_password_window,
            bg="white",
            font=("Arial", 12)
        )
        self.add_password_button.grid(row=0, column=1, padx=10)

        # Table Frame
        self.table_frame = tk.Frame(root, bg="#252420")
        self.table_frame.pack(pady=20)

        # Example data
        self.data = [
            {"Site": "Email", "Password": "Tan*567"},
            {"Site": "Instagram", "Password": "abc%123"},
            {"Site": "Discord", "Password": "vjtj@123"}
        ]

        print(self.pwd_dict)

        self.initial_pwd = {
            "email": "Tan@3456",
            "instagram": "Tanish$345"
        }
        # Create Table
        self.display_password_table()

    def display_password_table(self):
        """Displays the password table."""
        if os.path.exists("mypass.pass"):
            self.load_pwd_file("mypass.pass")
            print(self.pwd_dict)
        for widget in self.table_frame.winfo_children():
            widget.destroy()

        tk.Label(self.table_frame, text="Site", bg="#252420", fg="white", font=("Arial", 12, "bold")).grid(row=0, column=0, padx=10)
        tk.Label(self.table_frame, text="Password", bg="#252420", fg="white", font=("Arial", 12, "bold")).grid(row=0, column=1, padx=10)

        for i, (s, p) in enumerate(self.pwd_dict.items()):
            tk.Label(self.table_frame, text=s, bg="#252420", fg="white", font=("Arial", 12)).grid(row=i + 1, column=0, padx=10)
            password_label = tk.Label(self.table_frame, text="*" * len(p), bg="#252420", fg="white", font=("Arial", 12))
            password_label.grid(row=i + 1, column=1, padx=10)

            # Bind events to show and hide the password
            password_label.bind("<Enter>", lambda e, lbl=password_label, pwd=p: lbl.config(text=pwd))
            password_label.bind("<Leave>", lambda e, lbl=password_label, pwd=p: lbl.config(text="*" * len(pwd)))

    def add_password_window(self):
        """Opens a new window to add a password."""
        # Create a new top-level window
        print("Inside add_password_window()")

        add_window = tk.Toplevel(self.root)
        add_window.title("Add New Password")
        add_window.geometry("400x300")
        add_window.configure(bg="#252420")

        # Header
        header_label = tk.Label(add_window, text="Add a New Password", bg="#252420", fg="white", font=("Arial", 16, "bold"))
        header_label.pack(pady=20)

        # Site Entry
        site_label = tk.Label(add_window, text="Site:", bg="#252420", fg="white", font=("Arial", 12))
        site_label.pack(pady=5)
        site_entry = tk.Entry(add_window, width=30, font=("Arial", 12))
        site_entry.pack(pady=5)

        # Password Entry
        password_label = tk.Label(add_window, text="Password:", bg="#252420", fg="white", font=("Arial", 12))
        password_label.pack(pady=5)
        password_entry = tk.Entry(add_window, width=30, font=("Arial", 12))
        password_entry.pack(pady=5)

            # Save Button
        def save_password():
            site = site_entry.get().strip()
            password = password_entry.get().strip()

            if not site or not password:
                messagebox.showerror("Error", "Both fields are required!")
                return

            # Add new entry to the data
            self.add_pwd(site, password, "mypass.pass")
            self.data.append({"Site": site, "Password": password})
            self.display_password_table()
            add_window.destroy()
            messagebox.showinfo("Success", "New password added successfully!")

        save_button = tk.Button(
            add_window,
            text="Save",
            command=save_password,
            bg="yellow",
            font=("Arial", 12),
            width=15
        )
        save_button.pack(pady=20)

        # Instructions
        instructions_label = tk.Label(
            add_window,
            text="Make sure to save only strong passwords!",
            bg="#252420",
            fg="white",
            font=("Arial", 10)
        )
        instructions_label.pack(pady=5)

# Encryption Key Setup Window
class EncryptionSetupApp(VaultBackend):
    def __init__(self, root, username):
        super().__init__()
        self.root = root
        self.root.title("1Password - Encryption Setup")
        self.root.geometry("600x400")
        self.root.configure(bg="#252420")
        self.username = username

        # Header
        self.header_label = tk.Label(root, text="1Password", bg="#252420", fg="white", font=("Arial", 16, "bold"))
        self.header_label.pack(pady=20)

        # Welcome Message
        self.welcome_label = tk.Label(
            root, 
            text=f"Welcome to 1Password, {username}!", 
            bg="#252420", 
            fg="white", 
            font=("Arial", 14, "bold")
        )
        self.welcome_label.pack(pady=10)

        # Encryption Info
        self.encryption_info_label = tk.Label(
            root,
            text=(
                "We use AES-256 (Advanced Encryption Standard with a 256-bit key) as the primary\n"
                "encryption algorithm to encrypt your vault's contents.\n"
                "AES-256 is considered one of the most secure encryption algorithms available\n"
                "and is widely used in the industry."
            ),
            bg="#252420",
            fg="white",
            font=("Arial", 12),
            justify="center"
        )
        self.encryption_info_label.pack(pady=20)

        # Buttons
        self.button_frame = tk.Frame(root, bg="#252420")
        self.button_frame.pack(pady=20)

        self.generate_key_button = tk.Button(
            self.button_frame,
            text="Generate a new key",
            command=self.generate_key,
            bg="white",
            font=("Arial", 12),
            width=20
        )
        self.generate_key_button.grid(row=0, column=0, padx=10)

        self.load_key_button = tk.Button(
            self.button_frame,
            text="Load an existing key",
            command=self.load_key,
            bg="white",
            font=("Arial", 12),
            width=20
        )
        self.load_key_button.grid(row=0, column=1, padx=10)

    def generate_key(self):
        """Opens a new window to display the generated key.
        Generates a new encryption key."""
        self.create_key("finalkeys.key")
        with open("finalkeys.key", 'r') as f:
            generated_key = f.read()

        # Create a new top-level window
        key_window = tk.Toplevel(self.root)
        key_window.title("Generated Key")
        key_window.geometry("500x300")
        key_window.configure(bg="#252420")

        # Header
        header_label = tk.Label(key_window, text="Your Encryption Key", bg="#252420", fg="white", font=("Arial", 16, "bold"))
        header_label.pack(pady=20)

        # Display Key
        key_label = tk.Label(key_window, text="Here is your generated key:", bg="#252420", fg="white", font=("Arial", 12))
        key_label.pack(pady=10)

        key_entry = tk.Entry(key_window, width=40, font=("Arial", 14), justify="center")
        key_entry.insert(0, generated_key)
        key_entry.config(state="readonly")
        key_entry.pack(pady=10)

        # Copy Button
        def copy_to_clipboard():
            key_window.clipboard_clear()
            key_window.clipboard_append(generated_key)
            key_window.update()
            messagebox.showinfo("Copied", "Key copied to clipboard!")

            self.root.destroy()  # Close the login/signup window
            new_root = tk.Tk()
            PasswordManagerApp(new_root, self.username)
            new_root.mainloop()

        copy_button = tk.Button(
            key_window,
            text="Copy",
            command=copy_to_clipboard,
            bg="yellow",
            font=("Arial", 12),
            width=10
        )
        copy_button.pack(pady=20)

        # Instructions
        instructions_label = tk.Label(
            key_window,
            text="Keep this key safe! You will need it to access your encrypted data.",
            bg="#252420",
            fg="white",
            font=("Arial", 10)
        )
        instructions_label.pack(pady=20)
        
    def load_key(self):
        """Loads an existing encryption key (placeholder function)."""
        file_path = filedialog.askopenfilename(title="Select a File", filetypes=(("Key files", "*.key"), ("All files", "*.*")))
        self.load_existing_key(file_path)        

        messagebox.showinfo("Load Key", "An existing encryption key will be loaded.")

# Login/Signup GUI
class LoginSignupApp(VaultBackend):
    def __init__(self, root):
        super().__init__()
        self.root = root
        self.root.title("1Password Login/Signup")
        self.root.geometry("400x300")
        self.root.configure(bg="#252420")

        # Header
        self.header_label = tk.Label(root, text="1Password", bg="#252420", fg="white", font=("Arial", 16, "bold"))
        self.header_label.pack(pady=20)

        # Tabs for Login and Signup
        self.tab_frame = tk.Frame(root, bg="#252420")
        self.tab_frame.pack()

        self.login_button = tk.Button(self.tab_frame, text="Login", command=self.show_login, bg="yellow", width=10, font=("Arial", 12))
        self.login_button.grid(row=0, column=0)

        self.signup_button = tk.Button(self.tab_frame, text="Sign Up", command=self.show_signup, bg="gray", fg="white", width=10, font=("Arial", 12))
        self.signup_button.grid(row=0, column=1)

        # Form Frame
        self.form_frame = tk.Frame(root, bg="#252420")
        self.form_frame.pack(pady=20)

        # Username
        self.username_label = tk.Label(self.form_frame, text="Username:", bg="#252420", fg="white", font=("Arial", 12))
        self.username_label.grid(row=0, column=0, sticky="e", padx=10, pady=5)
        self.username_entry = tk.Entry(self.form_frame, width=25)
        self.username_entry.grid(row=0, column=1, pady=5)

        # Master Password
        self.password_label = tk.Label(self.form_frame, text="Master password:", bg="#252420", fg="white", font=("Arial", 12))
        self.password_label.grid(row=1, column=0, sticky="e", padx=10, pady=5)
        self.password_entry = tk.Entry(self.form_frame, width=25, show="*")
        self.password_entry.grid(row=1, column=1, pady=5)

        # Submit Button
        self.submit_button = tk.Button(root, text="Submit", command=self.process_form, bg="yellow", font=("Arial", 12))
        self.submit_button.pack(pady=10)

        # Default View
        self.current_mode = "Login"
        self.show_login()

    def show_login(self):
        """Switches to the login form."""
        self.current_mode = "Login"
        self.login_button.configure(bg="yellow", fg="#252420")
        self.signup_button.configure(bg="gray", fg="white")
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def show_signup(self):
        """Switches to the signup form."""
        self.current_mode = "Sign Up"
        self.signup_button.configure(bg="yellow", fg="#252420")
        self.login_button.configure(bg="gray", fg="white")
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def process_form(self):
        """Processes the form submission."""
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Both fields are required!")
            return

        if self.current_mode == "Login":
            self.handle_login(username, password)
        elif self.current_mode == "Sign Up":
            self.handle_signup(username, password)

    def handle_login(self, username, password):
        try:
            with open("./user_details.txt", 'r') as f:
                users = f.readlines()
                for user in users:
                    stored_username, stored_password = user.strip().split(":")
                    if stored_username == username and stored_password == password:
                        messagebox.showinfo("Login Successful", f"Welcome back, {username}!")
                        self.open_home(username)
                        return
            messagebox.showerror("Login Failed", "Invalid username or password.")
        except FileNotFoundError:
            messagebox.showerror("Login Failed", "No users found. Please sign up first.")

    def handle_signup(self, username, password):
        if os.path.exists("user_details.txt"):
            messagebox.showerror("SignUp Failed", "There is already one user signed in! Delete the prev user first")
            return
        else:
            with open("user_details.txt", 'a') as f:
                f.write(username + ":" + password + "\n")
            messagebox.showinfo("Signup Successful", f"Account created successfully, {username}!")
            self.open_encryption_setup(username)

    def open_home(self, username):
        self.root.destroy()  # Close the login/signup window
        new_root = tk.Tk()
        PasswordManagerApp(new_root, username)
        new_root.mainloop()

    def open_encryption_setup(self, username):
        """Opens the Encryption Setup window."""
        self.root.destroy()  # Close the login/signup window
        new_root = tk.Tk()
        EncryptionSetupApp(new_root, username)
        new_root.mainloop()

# Main Driver Code
if __name__ == "__main__":
    root = tk.Tk()
    root.config(bg="#252420")
    LoginSignupApp(root)
    root.mainloop()
