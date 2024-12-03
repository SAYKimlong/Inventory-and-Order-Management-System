import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from datetime import datetime
import hashlib
import re
import secrets  # For generating secure tokens
import smtplib
from email.mime.text import MIMEText

class DatabaseManager:
    @staticmethod
    def hash_password(password):
        """Create a secure hash of the password."""
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def generate_reset_token():
        """Generate a secure reset token."""
        return secrets.token_urlsafe(16)

    @staticmethod
    def initialize_databases():
        # Similar to previous implementation, with added users table modification
        users_conn = sqlite3.connect('users.db')
        users_cursor = users_conn.cursor()
        users_cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                email TEXT,
                reset_token TEXT,
                role TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Existing admin creation logic remains the same
        users_cursor.execute("SELECT * FROM users WHERE username = ?", ('admin',))
        if not users_cursor.fetchone():
            admin_password = DatabaseManager.hash_password('admin123')
            users_cursor.execute('''
                INSERT INTO users (username, password, role, email) 
                VALUES (?, ?, ?, ?)
            ''', ('admin', admin_password, 'administrator', 'admin@example.com'))
        
        users_conn.commit()
        users_conn.close()

class LoginPage:
    def __init__(self, root):
        DatabaseManager.initialize_databases()
        
        self.root = root
        self.root.title("Clothing Business Management Login")
        self.root.geometry("600x500")
        self.root.configure(bg='#f0f0f0')

        # Custom style
        style = ttk.Style()
        style.configure('TLabel', background='white', font=('Arial', 12))
        style.configure('TButton', font=('Arial', 12))
        style.configure('TEntry', font=('Arial', 12))

        # Main login frame
        login_frame = tk.Frame(self.root, bg='#ffffff', padx=40, pady=40, 
                               borderwidth=2, relief=tk.RAISED)
        login_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        # Title
        title_label = ttk.Label(login_frame, text="Clothing Business Management", 
                                font=("Arial", 16, "bold"))
        title_label.pack(pady=(0,20))

        # Username Label and Entry
        username_label = ttk.Label(login_frame, text="Username:")
        username_label.pack()
        self.username_entry = ttk.Entry(login_frame, width=30)
        self.username_entry.pack(pady=(0,10))

        # Password Label and Entry
        password_label = ttk.Label(login_frame, text="Password:")
        password_label.pack()
        self.password_entry = ttk.Entry(login_frame, show="*", width=30)
        self.password_entry.pack(pady=(0,20))

        # Login Button
        login_button = ttk.Button(login_frame, text="Login", command=self.login, width=20)
        login_button.pack(pady=(0,10))

        # Forgot Password Link
        forgot_password_link = ttk.Label(login_frame, text="Forgot Password?", 
                                         foreground="blue", cursor="hand2")
        forgot_password_link.pack(pady=(0,10))
        forgot_password_link.bind("<Button-1>", self.forgot_password)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Login Error", "Please enter both username and password")
            return

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        hashed_password = DatabaseManager.hash_password(password)
        
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_password))
        user = cursor.fetchone()
        conn.close()

        if user:
            self.root.destroy()
            main_root = tk.Tk()
            app = MainPage(main_root, username)
            main_root.mainloop()
        else:
            messagebox.showerror("Login Failed", "Incorrect Username or Password")

    def forgot_password(self, event):
        # Improved password reset dialog
        reset_window = tk.Toplevel(self.root)
        reset_window.title("Password Reset")
        reset_window.geometry("400x300")
        reset_window.configure(bg='#f0f0f0')

        # Username Entry
        ttk.Label(reset_window, text="Username:").pack(pady=(20, 5))
        username_entry = ttk.Entry(reset_window, width=30)
        username_entry.pack(pady=(0, 10))

        # Email Entry
        ttk.Label(reset_window, text="Email:").pack(pady=(10, 5))
        email_entry = ttk.Entry(reset_window, width=30)
        email_entry.pack(pady=(0, 20))

        def submit_reset():
            username = username_entry.get()
            email = email_entry.get()

            if not username or not email:
                messagebox.showerror("Error", "Please enter both username and email")
                return

            # Validate user exists
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ? AND email = ?", (username, email))
            user = cursor.fetchone()

            if user:
                # Generate reset token
                reset_token = DatabaseManager.generate_reset_token()
                
                # Update database with reset token
                cursor.execute("UPDATE users SET reset_token = ? WHERE username = ?", 
                               (reset_token, username))
                conn.commit()
                
                # In a real app, you would send an email. Here we'll show the token.
                messagebox.showinfo("Reset Instructions", 
                    f"A password reset link has been generated.\n"
                    f"Reset Token: {reset_token}\n"
                    "Please use this token to reset your password.")
                
                # Open new window to enter reset token and new password
                reset_confirmation_window(reset_window, username, reset_token)
            else:
                messagebox.showerror("Error", "Username and email do not match")
            
            conn.close()

        def reset_confirmation_window(parent, username, reset_token):
            # New window for token and password entry
            confirm_window = tk.Toplevel(parent)
            confirm_window.title("Confirm Reset")
            confirm_window.geometry("400x300")

            ttk.Label(confirm_window, text="Enter Reset Token:").pack(pady=(20, 5))
            token_entry = ttk.Entry(confirm_window, width=30)
            token_entry.pack(pady=(0, 10))

            ttk.Label(confirm_window, text="New Password:").pack(pady=(10, 5))
            new_password_entry = ttk.Entry(confirm_window, show="*", width=30)
            new_password_entry.pack(pady=(0, 10))

            ttk.Label(confirm_window, text="Confirm New Password:").pack(pady=(10, 5))
            confirm_password_entry = ttk.Entry(confirm_window, show="*", width=30)
            confirm_password_entry.pack(pady=(0, 20))

            def confirm_reset():
                entered_token = token_entry.get()
                new_password = new_password_entry.get()
                confirm_password = confirm_password_entry.get()

                if not entered_token or not new_password or not confirm_password:
                    messagebox.showerror("Error", "Please fill all fields")
                    return

                if new_password != confirm_password:
                    messagebox.showerror("Error", "Passwords do not match")
                    return

                if not LoginPage.is_password_strong(new_password):
                    messagebox.showerror("Password Error", 
                        "Password is too weak. Must be at least 8 characters with mix of uppercase, lowercase, numbers, and symbols.")
                    return

                conn = sqlite3.connect('users.db')
                cursor = conn.cursor()
                
                # Validate token
                cursor.execute("""
                    SELECT * FROM users 
                    WHERE username = ? AND reset_token = ?
                """, (username, entered_token))
                
                user = cursor.fetchone()
                if user:
                    # Hash and update password, clear reset token
                    hashed_password = DatabaseManager.hash_password(new_password)
                    cursor.execute("""
                        UPDATE users 
                        SET password = ?, reset_token = NULL 
                        WHERE username = ?
                    """, (hashed_password, username))
                    conn.commit()
                    
                    messagebox.showinfo("Success", "Password reset successfully!")
                    confirm_window.destroy()
                    parent.destroy()
                else:
                    messagebox.showerror("Error", "Invalid reset token")
                
                conn.close()

            reset_button = ttk.Button(confirm_window, text="Reset Password", command=confirm_reset)
            reset_button.pack(pady=20)

        submit_button = ttk.Button(reset_window, text="Submit", command=submit_reset)
        submit_button.pack(pady=20)

    @staticmethod
    def is_password_strong(password):
        # Existing robust password strength check
        if len(password) < 8:
            return False
        
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'\d', password):
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        
        return True

    def __init__(self, root):
        # Initialize databases
        DatabaseManager.initialize_databases()
        
        self.root = root
        self.root.title("Clothing Business Management Login")
        self.root.geometry("500x400")
        self.root.configure(bg='#f0f0f0')

        # Main login frame
        login_frame = tk.Frame(self.root, bg='#ffffff', padx=30, pady=30, borderwidth=2, relief=tk.RAISED)
        login_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        # Title
        title_label = tk.Label(login_frame, text="Clothing Business Management", 
                               font=("Arial", 16, "bold"), bg='white')
        title_label.pack(pady=(0,20))

        # Username Label and Entry
        username_label = tk.Label(login_frame, text="Username:", bg='white', font=("Arial", 12))
        username_label.pack()
        self.username_entry = tk.Entry(login_frame, width=30, font=("Arial", 12))
        self.username_entry.pack(pady=(0,10))

        # Password Label and Entry
        password_label = tk.Label(login_frame, text="Password:", bg='white', font=("Arial", 12))
        password_label.pack()
        self.password_entry = tk.Entry(login_frame, show="*", width=30, font=("Arial", 12))
        self.password_entry.pack(pady=(0,20))

        # Login Button with improved styling
        login_button = tk.Button(login_frame, text="Login", command=self.login, 
                                 width=20, bg='#4CAF50', fg='white', font=("Arial", 12, "bold"))
        login_button.pack(pady=(0,10))

        # Forgot Password Link
        forgot_password_link = tk.Label(login_frame, text="Forgot Password?", fg='blue', bg='white', cursor="hand2")
        forgot_password_link.pack(pady=(0,10))
        forgot_password_link.bind("<Button-1>", self.forgot_password)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        # Validate input
        if not username or not password:
            messagebox.showerror("Login Error", "Please enter both username and password")
            return

        # Check credentials
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Hash the entered password
        hashed_password = DatabaseManager.hash_password(password)
        
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_password))
        user = cursor.fetchone()
        conn.close()

        if user:
            # Successful login
            self.root.destroy()  # Close login window
            main_root = tk.Tk()
            app = MainPage(main_root, username)
            app.run()
        else:
            messagebox.showerror("Login Failed", "Incorrect Username or Password")

    def forgot_password(self, event):
        # Simple password reset mechanism
        username = simpledialog.askstring("Forgot Password", "Enter your username:")
        if username:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            conn.close()

            if user:
                # In a real application, this would be more secure
                new_password = simpledialog.askstring("Reset Password", "Enter new password:", show='*')
                if new_password:
                    # Validate password strength
                    if not self.is_password_strong(new_password):
                        messagebox.showerror("Password Error", "Password is too weak. Must be at least 8 characters with mix of uppercase, lowercase, numbers, and symbols.")
                        return

                    # Hash and update password
                    hashed_password = DatabaseManager.hash_password(new_password)
                    conn = sqlite3.connect('users.db')
                    cursor = conn.cursor()
                    cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
                    conn.commit()
                    conn.close()
                    messagebox.showinfo("Success", "Password updated successfully!")
            else:
                messagebox.showerror("Error", "Username not found")

    def is_password_strong(self, password):
        # Check password strength
        if len(password) < 8:
            return False
        
        # Check for at least one uppercase, one lowercase, one number, and one special character
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'\d', password):
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        
        return True


class ModernStyle:
    """Define a modern, cohesive color scheme and styling"""
    PRIMARY_COLOR = "#2C3E50"  # Deep blue-gray
    SECONDARY_COLOR = "#34495E"  # Slightly lighter blue-gray
    ACCENT_COLOR = "#3498DB"  # Bright blue
    BACKGROUND_COLOR = "#ECF0F1"  # Light gray-white
    TEXT_COLOR = "#FFFFFF"  # White
    FONT_FAMILY = "Segoe UI"

class MainPage:
    def __init__(self, root, username):
        self.root = root
        self.username = username
        self.root.title(f"Clothing Business Management")
        self.root.geometry("700x600")
        self.root.configure(bg=ModernStyle.BACKGROUND_COLOR)
        
        # Create main frame with modern styling
        self.main_frame = tk.Frame(self.root, bg=ModernStyle.BACKGROUND_COLOR)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Custom title design
        title_frame = tk.Frame(self.main_frame, bg=ModernStyle.PRIMARY_COLOR)
        title_frame.pack(fill=tk.X, pady=(0, 30))
        
        title_label = tk.Label(
            title_frame, 
            text=f"Welcome, {username}", 
            font=(ModernStyle.FONT_FAMILY, 24, "bold"),
            fg=ModernStyle.TEXT_COLOR, 
            bg=ModernStyle.PRIMARY_COLOR,
            pady=15
        )
        title_label.pack()
        
        # Modern button style
        button_style = {
            "font": (ModernStyle.FONT_FAMILY, 14),
            "bg": ModernStyle.ACCENT_COLOR,
            "fg": ModernStyle.TEXT_COLOR,
            "activebackground": ModernStyle.SECONDARY_COLOR,
            "relief": tk.FLAT,
            "width": 30
        }
        
        # Inventory Management Button
        self.inventory_btn = tk.Button(
            self.main_frame, 
            text="Inventory Management", 
            command=self.open_inventory_system,
            **button_style
        )
        self.inventory_btn.pack(pady=15)
        
        # Order Management Button
        self.order_btn = tk.Button(
            self.main_frame, 
            text="Order Management", 
            command=self.open_order_system,
            **button_style
        )
        self.order_btn.pack(pady=15)

        # Logout Button
        self.logout_btn = tk.Button(
            self.main_frame, 
            text="Logout", 
            command=self.logout,
            **{**button_style, "bg": "#E74C3C"}  # Red color for logout
        )
        self.logout_btn.pack(pady=15)

    def open_inventory_system(self):
        inventory_window = tk.Toplevel(self.root)
        InventoryManagementSystem(inventory_window, self.root)
    
    def open_order_system(self):
        order_window = tk.Toplevel(self.root)
        OrderManagementSystem(order_window, self.root)
    
    def logout(self):
        self.root.destroy()
        login_root = tk.Tk()
        LoginPage(login_root)
        login_root.mainloop()

class InventoryManagementSystem:
    def __init__(self, parent_root, main_window):
        self.root = parent_root
        self.main_window = main_window
        self.root.title("Inventory Management")
        self.root.geometry("1200x800")
        self.root.configure(bg=ModernStyle.BACKGROUND_COLOR)
        
        # Initialize database
        self.init_database()
        
        # Main container
        main_container = tk.Frame(self.root, bg=ModernStyle.BACKGROUND_COLOR)
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title_frame = tk.Frame(main_container, bg=ModernStyle.PRIMARY_COLOR)
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        title_label = tk.Label(
            title_frame, 
            text="Inventory Management", 
            font=(ModernStyle.FONT_FAMILY, 24, "bold"),
            fg=ModernStyle.TEXT_COLOR, 
            bg=ModernStyle.PRIMARY_COLOR,
            pady=15
        )
        title_label.pack()
        
        # Form Frame
        form_frame = tk.Frame(main_container, bg=ModernStyle.BACKGROUND_COLOR)
        form_frame.pack(fill=tk.X, pady=10)
        
        entry_style = {
            "font": (ModernStyle.FONT_FAMILY, 12),
            "bd": 2,
            "relief": tk.FLAT
        }
        
        # Input fields with labels
        self.fields = [
            ("Item Name", self.create_entry(form_frame, **entry_style)),
            ("Category", self.create_dropdown(form_frame, ["Shirts", "Pants", "Dresses", "Accessories"])),
            ("Size", self.create_dropdown(form_frame, ["XS", "S", "M", "L", "XL", "XXL"])),
            ("Color", self.create_entry(form_frame, **entry_style)),
            ("Quantity", self.create_entry(form_frame, **entry_style)),
            ("Reorder Level", self.create_entry(form_frame, **entry_style))
        ]
        
        for i, (label_text, entry_widget) in enumerate(self.fields):
            tk.Label(
                form_frame, 
                text=f"{label_text}:", 
                font=(ModernStyle.FONT_FAMILY, 12),
                bg=ModernStyle.BACKGROUND_COLOR
            ).grid(row=i, column=0, sticky="w", padx=10, pady=5)
            entry_widget.grid(row=i, column=1, padx=10, pady=5, sticky="ew")
        
        form_frame.columnconfigure(1, weight=1)
        
        # Buttons with modern styling
        button_frame = tk.Frame(main_container, bg=ModernStyle.BACKGROUND_COLOR)
        button_frame.pack(fill=tk.X, pady=10)
        
        button_style = {
            "font": (ModernStyle.FONT_FAMILY, 12),
            "bg": ModernStyle.ACCENT_COLOR,
            "fg": ModernStyle.TEXT_COLOR,
            "activebackground": ModernStyle.SECONDARY_COLOR,
            "relief": tk.FLAT,
            "padx": 20,
            "pady": 10
        }
        
        buttons = [
            ("Add Item", self.add_item),
            ("Update Item", self.update_item),
            ("Delete Item", self.delete_item),
            ("Clear Form", self.clear_form)
        ]
        
        for text, command in buttons:
            btn = tk.Button(button_frame, text=text, command=command, **button_style)
            btn.pack(side=tk.LEFT, padx=10)
        
        # Treeview for displaying items
        self.create_item_display(main_container)
        
        # Return home button
        return_btn = tk.Button(
            main_container, 
            text="Return to Home", 
            command=self.return_home,
            **{**button_style, "bg": ModernStyle.SECONDARY_COLOR}
        )
        return_btn.pack(pady=10)

    def init_database(self):
        """Initialize the inventory database"""
        try:
            self.conn = sqlite3.connect('clothing_business.db')
            self.cursor = self.conn.cursor()
            
            # Create inventory table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS inventory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_name TEXT UNIQUE,
                    category TEXT,
                    size TEXT,
                    color TEXT,
                    quantity INTEGER,
                    reorder_level INTEGER,
                    last_updated DATETIME
                )
            ''')
            
            self.conn.commit()
        
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to initialize database: {e}")

    def create_entry(self, parent, **kwargs):
        return tk.Entry(parent, **kwargs)

    def create_dropdown(self, parent, values):
        var = tk.StringVar()
        dropdown = ttk.Combobox(
            parent, 
            textvariable=var, 
            values=values,
            font=(ModernStyle.FONT_FAMILY, 12)
        )
        return dropdown

    def add_item(self):
        """Add a new item to the inventory"""
        try:
            # Collect item details from form
            item_name = self.fields[0][1].get()
            category = self.fields[1][1].get()
            size = self.fields[2][1].get()
            color = self.fields[3][1].get()
            quantity = int(self.fields[4][1].get())
            reorder_level = int(self.fields[5][1].get())
            
            # Validate input
            if not all([item_name, category, size, color, quantity, reorder_level]):
                messagebox.showerror("Input Error", "Please fill all fields")
                return
            
            # Insert item
            last_updated = datetime.now()
            self.cursor.execute('''
                INSERT INTO inventory 
                (item_name, category, size, color, quantity, reorder_level, last_updated) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (item_name, category, size, color, quantity, reorder_level, last_updated))
            
            self.conn.commit()
            
            # Refresh displays
            self.refresh_item_display()
            self.clear_form()
            messagebox.showinfo("Success", "Item added successfully")
        
        except (sqlite3.IntegrityError):
            messagebox.showerror("Error", "An item with this name already exists")
        except (sqlite3.Error, ValueError) as e:
            messagebox.showerror("Error", str(e))

    def update_item(self):
        """Update an existing inventory item"""
        try:
            # Get selected item
            selected_item = self.item_tree.selection()
            if not selected_item:
                messagebox.showerror("Selection Error", "Please select an item to update")
                return
            
            # Collect updated details
            item_name = self.fields[0][1].get()
            category = self.fields[1][1].get()
            size = self.fields[2][1].get()
            color = self.fields[3][1].get()
            quantity = int(self.fields[4][1].get())
            reorder_level = int(self.fields[5][1].get())
            
            # Validate input
            if not all([item_name, category, size, color, quantity, reorder_level]):
                messagebox.showerror("Input Error", "Please fill all fields")
                return
            
            # Update item
            last_updated = datetime.now()
            self.cursor.execute('''
                UPDATE inventory 
                SET category=?, size=?, color=?, quantity=?, 
                    reorder_level=?, last_updated=? 
                WHERE item_name = ?
            ''', (category, size, color, quantity, reorder_level, last_updated, item_name))
            
            self.conn.commit()
            
            # Refresh displays
            self.refresh_item_display()
            self.clear_form()
            messagebox.showinfo("Success", "Item updated successfully")
        
        except (sqlite3.Error, ValueError) as e:
            messagebox.showerror("Error", str(e))

    def delete_item(self):
        """Delete an existing inventory item"""
        try:
            # Get selected item
            selected_item = self.item_tree.selection()
            if not selected_item:
                messagebox.showerror("Selection Error", "Please select an item to delete")
                return
            
            # Confirm deletion
            if messagebox.askyesno("Confirm", "Are you sure you want to delete this item?"):
                # Get item name to delete
                item_details = self.item_tree.item(selected_item)['values']
                item_name = item_details[0]
                
                # Delete item
                self.cursor.execute("DELETE FROM inventory WHERE item_name = ?", (item_name,))
                
                self.conn.commit()
                
                # Refresh displays
                self.refresh_item_display()
                self.clear_form()
                messagebox.showinfo("Success", "Item deleted successfully")
        
        except sqlite3.Error as e:
            messagebox.showerror("Error", str(e))

    def refresh_item_display(self):
        """Refresh the item treeview with current database contents"""
        # Clear existing items
        for i in self.item_tree.get_children():
            self.item_tree.delete(i)
        
        # Fetch and display items
        try:
            self.cursor.execute("SELECT * FROM inventory ORDER BY last_updated DESC")
            for item in self.cursor.fetchall():
                # Format item data for display (skipping id, using item[6] as last_updated)
                formatted_item = (
                    item[1],  # item_name
                    item[2],  # category
                    item[3],  # size
                    item[4],  # color
                    item[5],  # quantity
                    item[6],  # reorder_level
                    item[7]   # last_updated
                )
                self.item_tree.insert("", "end", values=formatted_item)
        
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to retrieve items: {e}")

    def on_item_select(self, event):
        """Handle item selection in the treeview"""
        selected_item = self.item_tree.selection()
        if selected_item:
            # Get selected item details
            item = self.item_tree.item(selected_item)['values']
            
            # Populate form fields
            for i, value in enumerate([item[0], item[1], item[2], item[3], item[4], item[5]]):
                # Clear existing text
                if isinstance(self.fields[i][1], tk.Entry):
                    self.fields[i][1].delete(0, tk.END)
                    self.fields[i][1].insert(0, value)
                elif isinstance(self.fields[i][1], ttk.Combobox):
                    self.fields[i][1].set(value)

    def clear_form(self):
        """Clear all form fields"""
        for _, entry in self.fields:
            if isinstance(entry, tk.Entry):
                entry.delete(0, tk.END)
            elif isinstance(entry, ttk.Combobox):
                entry.set('')

    def return_home(self):
        """Return to the main window"""
        self.root.destroy()

    def create_item_display(self, parent):
        """Create treeview for displaying inventory items"""
        # Treeview with modern styling
        columns = ("Name", "Category", "Size", "Color", "Quantity", "Reorder Level", "Last Updated")
        self.item_tree = ttk.Treeview(
            parent, 
            columns=columns,
            show='headings',
            selectmode='browse',
            style='Modern.Treeview'
        )
        
        # Configure treeview style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Modern.Treeview', 
                        background=ModernStyle.BACKGROUND_COLOR, 
                        foreground='black',
                        rowheight=30,
                        font=(ModernStyle.FONT_FAMILY, 10))
        style.configure('Modern.Treeview.Heading', 
                        background=ModernStyle.PRIMARY_COLOR, 
                        foreground=ModernStyle.TEXT_COLOR,
                        font=(ModernStyle.FONT_FAMILY, 12, 'bold'))
        
        # Configure columns
        for col in columns:
            self.item_tree.heading(col, text=col, anchor='center')
            self.item_tree.column(col, anchor='center', width=120)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.item_tree.yview)
        self.item_tree.configure(yscrollcommand=scrollbar.set)
        
        # Layout
        self.item_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,10), pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
        # Bind selection event
        self.item_tree.bind('<<TreeviewSelect>>', self.on_item_select)
        
        # Refresh display
        self.refresh_item_display()

    def __del__(self):
        """Ensure database connection is closed"""
        if hasattr(self, 'conn'):
            self.conn.close()
class OrderManagementSystem:
    def __init__(self, parent_root, main_window):
        self.root = parent_root
        self.main_window = main_window
        self.root.title("Order Management")
        self.root.geometry("1200x800")
        self.root.configure(bg=ModernStyle.BACKGROUND_COLOR)
        
        # Initialize database
        self.init_database()
        
        # Main container
        main_container = tk.Frame(self.root, bg=ModernStyle.BACKGROUND_COLOR)
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title_frame = tk.Frame(main_container, bg=ModernStyle.PRIMARY_COLOR)
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        title_label = tk.Label(
            title_frame, 
            text="Order Management", 
            font=(ModernStyle.FONT_FAMILY, 24, "bold"),
            fg=ModernStyle.TEXT_COLOR, 
            bg=ModernStyle.PRIMARY_COLOR,
            pady=15
        )
        title_label.pack()
        
        # Form Frame
        form_frame = tk.Frame(main_container, bg=ModernStyle.BACKGROUND_COLOR)
        form_frame.pack(fill=tk.X, pady=10)
        
        entry_style = {
            "font": (ModernStyle.FONT_FAMILY, 12),
            "bd": 2,
            "relief": tk.FLAT
        }
        
        # Input fields with labels
        self.fields = [
            ("Customer Name", self.create_entry(form_frame, **entry_style)),
            ("Item Name", self.create_dropdown(form_frame, self.inventory_items)),
            ("Quantity", self.create_entry(form_frame, **entry_style)),
            ("Total Price", self.create_entry(form_frame, **entry_style)),
            ("Status", self.create_dropdown(form_frame, ["Pending", "Processing", "Shipped", "Delivered", "Cancelled"]))
        ]
        
        for i, (label_text, entry_widget) in enumerate(self.fields):
            tk.Label(
                form_frame, 
                text=f"{label_text}:", 
                font=(ModernStyle.FONT_FAMILY, 12),
                bg=ModernStyle.BACKGROUND_COLOR
            ).grid(row=i, column=0, sticky="w", padx=10, pady=5)
            entry_widget.grid(row=i, column=1, padx=10, pady=5, sticky="ew")
        
        form_frame.columnconfigure(1, weight=1)
        
        # Buttons with modern styling
        button_frame = tk.Frame(main_container, bg=ModernStyle.BACKGROUND_COLOR)
        button_frame.pack(fill=tk.X, pady=10)
        
        button_style = {
            "font": (ModernStyle.FONT_FAMILY, 12),
            "bg": ModernStyle.ACCENT_COLOR,
            "fg": ModernStyle.TEXT_COLOR,
            "activebackground": ModernStyle.SECONDARY_COLOR,
            "relief": tk.FLAT,
            "padx": 20,
            "pady": 10
        }
        
        buttons = [
            ("Add Order", self.add_order),
            ("Update Order", self.update_order),
            ("Delete Order", self.delete_order)
        ]
        
        for text, command in buttons:
            btn = tk.Button(button_frame, text=text, command=command, **button_style)
            btn.pack(side=tk.LEFT, padx=10)
        
        # Create Order Display
        self.create_order_display(main_container)
        
        # Return home button
        return_btn = tk.Button(
            main_container, 
            text="Return to Home", 
            command=self.return_home,
            **{**button_style, "bg": ModernStyle.SECONDARY_COLOR}
        )
        return_btn.pack(pady=10)

    def init_database(self):
        """Initialize the orders database"""
        # (Database initialization code omitted for brevity)

    def add_order(self):
        """Add a new order to the database"""
        try:
            # (Add order code omitted for brevity)
            self.refresh_order_display()
            self.clear_form()
            messagebox.showinfo("Success", "Order added successfully")
        except (sqlite3.Error, ValueError) as e:
            messagebox.showerror("Error", str(e))

    def update_order(self):
        """Update an existing order"""
        try:
            # (Update order code omitted for brevity)
            self.refresh_order_display()
            self.clear_form()
            messagebox.showinfo("Success", "Order updated successfully")
        except (sqlite3.Error, ValueError) as e:
            messagebox.showerror("Error", str(e))

    def delete_order(self):
        """Delete an existing order"""
        try:
            # (Delete order code omitted for brevity)
            self.refresh_order_display()
            self.clear_form()
            messagebox.showinfo("Success", "Order deleted successfully")
        except sqlite3.Error as e:
            messagebox.showerror("Error", str(e))

    def refresh_order_display(self):
        """Refresh the order treeview with current database contents"""
        # Clear existing items
        for i in self.order_tree.get_children():
            self.order_tree.delete(i)
        
        # Fetch and display orders
        try:
            self.cursor.execute("SELECT * FROM orders ORDER BY order_date DESC")
            for order in self.cursor.fetchall():
                # Format order data for display
                formatted_order = (
                    order[1],  # customer_name
                    order[2],  # item_name
                    order[3],  # quantity
                    f"${order[4]:.2f}",  # total_price
                    order[5],  # status
                    order[6]   # order_date
                )
                self.order_tree.insert("", "end", values=formatted_order)
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to retrieve orders: {e}")

    def on_order_select(self, event):
        """Handle order selection in the treeview"""
        selected_item = self.order_tree.selection()
        if selected_item:
            # Get selected order details
            order = self.order_tree.item(selected_item)['values']
            
            # Populate form fields
            self.fields[0][1].delete(0, tk.END)
            self.fields[0][1].insert(0, order[0])  # Customer Name
            
            self.fields[1][1].set(order[1])  # Item Name
            
            self.fields[2][1].delete(0, tk.END)
            self.fields[2][1].insert(0, order[2])  # Quantity
            
            self.fields[3][1].delete(0, tk.END)
            self.fields[3][1].insert(0, order[3].replace('$', ''))  # Total Price
            
            self.fields[4][1].set(order[4])  # Status
            
            # Store current order ID for updates/deletion
            self.current_order_id = order[5] if len(order) > 5 else None

    def clear_form(self):
        """Clear all form fields"""
        for _, entry in self.fields:
            if isinstance(entry, tk.Entry):
                entry.delete(0, tk.END)
            elif isinstance(entry, ttk.Combobox):
                entry.set('')

    def return_home(self):
        """Return to the main window"""
        self.root.destroy()

    def __del__(self):
        """Ensure database connection is closed"""
        if hasattr(self, 'conn'):
            self.conn.close()

    def create_order_display(self, parent):
        # Treeview with modern styling
        columns = ("Customer Name", "Item Name", "Quantity", "Total Price", "Status", "Order Date")
        self.order_tree = ttk.Treeview(
            parent, 
            columns=columns,
            show='headings',
            selectmode='browse',
            style='Modern.Treeview'
        )
        
        # Configure treeview style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Modern.Treeview', 
                        background=ModernStyle.BACKGROUND_COLOR, 
                        foreground='black',
                        rowheight=30,
                        font=(ModernStyle.FONT_FAMILY, 10))
        style.configure('Modern.Treeview.Heading', 
                        background=ModernStyle.PRIMARY_COLOR, 
                        foreground=ModernStyle.TEXT_COLOR,
                        font=(ModernStyle.FONT_FAMILY, 12, 'bold'))
        
        # Configure columns
        for col in columns:
            self.order_tree.heading(col, text=col, anchor='center')
            self.order_tree.column(col, anchor='center', width=120)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.order_tree.yview)
        self.order_tree.configure(yscrollcommand=scrollbar.set)
        
        # Layout
        self.order_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,10), pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
        # Bind selection event
        self.order_tree.bind('<<TreeviewSelect>>', self.on_order_select)
        
        # Refresh display
        self.refresh_order_display()

    def create_entry(self, parent, **kwargs):
        return tk.Entry(parent, **kwargs)

    def create_dropdown(self, parent, values):
        var = tk.StringVar()
        dropdown = ttk.Combobox(
            parent, 
            textvariable=var, 
            values=values,
            font=(ModernStyle.FONT_FAMILY, 12)
        )
        return dropdown
    def __init__(self, parent_root, main_window):
        self.root = parent_root
        self.main_window = main_window
        self.root.title("Order Management")
        self.root.geometry("1200x800")
        self.root.configure(bg=ModernStyle.BACKGROUND_COLOR)
        
        # Initialize database
        self.init_database()
        
        # Main container
        main_container = tk.Frame(self.root, bg=ModernStyle.BACKGROUND_COLOR)
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title_frame = tk.Frame(main_container, bg=ModernStyle.PRIMARY_COLOR)
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        title_label = tk.Label(
            title_frame, 
            text="Order Management", 
            font=(ModernStyle.FONT_FAMILY, 24, "bold"),
            fg=ModernStyle.TEXT_COLOR, 
            bg=ModernStyle.PRIMARY_COLOR,
            pady=15
        )
        title_label.pack()
        
        # Form Frame
        form_frame = tk.Frame(main_container, bg=ModernStyle.BACKGROUND_COLOR)
        form_frame.pack(fill=tk.X, pady=10)
        
        entry_style = {
            "font": (ModernStyle.FONT_FAMILY, 12),
            "bd": 2,
            "relief": tk.FLAT
        }
        
        # Input fields with labels
        self.fields = [
            ("Customer Name", self.create_entry(form_frame, **entry_style)),
            ("Item Name", self.create_dropdown(form_frame, self.inventory_items)),
            ("Quantity", self.create_entry(form_frame, **entry_style)),
            ("Total Price", self.create_entry(form_frame, **entry_style)),
            ("Status", self.create_dropdown(form_frame, ["Pending", "Processing", "Shipped", "Delivered", "Cancelled"]))
        ]
        
        for i, (label_text, entry_widget) in enumerate(self.fields):
            tk.Label(
                form_frame, 
                text=f"{label_text}:", 
                font=(ModernStyle.FONT_FAMILY, 12),
                bg=ModernStyle.BACKGROUND_COLOR
            ).grid(row=i, column=0, sticky="w", padx=10, pady=5)
            entry_widget.grid(row=i, column=1, padx=10, pady=5, sticky="ew")
        
        form_frame.columnconfigure(1, weight=1)
        
        # Buttons with modern styling
        button_frame = tk.Frame(main_container, bg=ModernStyle.BACKGROUND_COLOR)
        button_frame.pack(fill=tk.X, pady=10)
        
        button_style = {
            "font": (ModernStyle.FONT_FAMILY, 12),
            "bg": ModernStyle.ACCENT_COLOR,
            "fg": ModernStyle.TEXT_COLOR,
            "activebackground": ModernStyle.SECONDARY_COLOR,
            "relief": tk.FLAT,
            "padx": 20,
            "pady": 10
        }
        
        buttons = [
            ("Add Order", self.add_order),
            ("Update Order", self.update_order),
            ("Delete Order", self.delete_order)
        ]
        
        for text, command in buttons:
            btn = tk.Button(button_frame, text=text, command=command, **button_style)
            btn.pack(side=tk.LEFT, padx=10)
        
        # Treeview for displaying orders
        self.create_order_display(main_container)
        
        # Return home button
        return_btn = tk.Button(
            main_container, 
            text="Return to Home", 
            command=self.return_home,
            **{**button_style, "bg": ModernStyle.SECONDARY_COLOR}
        )
        return_btn.pack(pady=10)

    def init_database(self):
        """Initialize the orders database"""
        try:
            self.conn = sqlite3.connect('clothing_business.db')
            self.cursor = self.conn.cursor()
            
            # Create orders table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS orders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    customer_name TEXT,
                    item_name TEXT,
                    quantity INTEGER,
                    total_price REAL,
                    status TEXT,
                    order_date DATETIME
                )
            ''')
            
            # Create inventory table to get item names
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS inventory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_name TEXT,
                    category TEXT,
                    size TEXT,
                    color TEXT,
                    quantity INTEGER,
                    reorder_level INTEGER
                )
            ''')
            
            self.conn.commit()
            
            # Fetch inventory items for dropdown
            self.cursor.execute("SELECT item_name FROM inventory")
            self.inventory_items = [item[0] for item in self.cursor.fetchall()]
        
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to initialize database: {e}")

    def add_order(self):
        """Add a new order to the database"""
        try:
            # Collect order details from form
            customer_name = self.fields[0][1].get()
            item_name = self.fields[1][1].get()
            quantity = int(self.fields[2][1].get())
            total_price = float(self.fields[3][1].get())
            status = self.fields[4][1].get()
            
            # Validate input
            if not all([customer_name, item_name, quantity, total_price, status]):
                messagebox.showerror("Input Error", "Please fill all fields")
                return
            
            # Check inventory availability
            self.cursor.execute("SELECT quantity FROM inventory WHERE item_name = ?", (item_name,))
            current_stock = self.cursor.fetchone()
            
            if not current_stock or current_stock[0] < quantity:
                messagebox.showerror("Inventory Error", "Insufficient stock")
                return
            
            # Insert order
            order_date = datetime.now()
            self.cursor.execute('''
                INSERT INTO orders 
                (customer_name, item_name, quantity, total_price, status, order_date) 
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (customer_name, item_name, quantity, total_price, status, order_date))
            
            # Update inventory
            self.cursor.execute('''
                UPDATE inventory 
                SET quantity = quantity - ? 
                WHERE item_name = ?
            ''', (quantity, item_name))
            
            self.conn.commit()
            
            # Refresh displays
            self.refresh_order_display()
            self.clear_form()
            messagebox.showinfo("Success", "Order added successfully")
        
        except (sqlite3.Error, ValueError) as e:
            messagebox.showerror("Error", str(e))

    def update_order(self):
        """Update an existing order"""
        try:
            # Get selected order
            selected_item = self.order_tree.selection()
            if not selected_item:
                messagebox.showerror("Selection Error", "Please select an order to update")
                return
            
            # Collect updated details
            customer_name = self.fields[0][1].get()
            item_name = self.fields[1][1].get()
            quantity = int(self.fields[2][1].get())
            total_price = float(self.fields[3][1].get())
            status = self.fields[4][1].get()
            
            # Validate input
            if not all([customer_name, item_name, quantity, total_price, status]):
                messagebox.showerror("Input Error", "Please fill all fields")
                return
            
            # Get original order details to handle inventory adjustment
            original_order = self.order_tree.item(selected_item)['values']
            original_quantity = original_order[2]
            original_item = original_order[1]
            
            # Update order
            self.cursor.execute('''
                UPDATE orders 
                SET customer_name=?, item_name=?, quantity=?, 
                    total_price=?, status=? 
                WHERE id = ?
            ''', (customer_name, item_name, quantity, total_price, status, 
                  self.current_order_id))
            
            # Adjust inventory
            if item_name != original_item or quantity != original_quantity:
                # Restore original item's quantity
                self.cursor.execute('''
                    UPDATE inventory 
                    SET quantity = quantity + ? 
                    WHERE item_name = ?
                ''', (original_quantity, original_item))
                
                # Reduce new item's quantity
                self.cursor.execute('''
                    UPDATE inventory 
                    SET quantity = quantity - ? 
                    WHERE item_name = ?
                ''', (quantity, item_name))
            
            self.conn.commit()
            
            # Refresh displays
            self.refresh_order_display()
            self.clear_form()
            messagebox.showinfo("Success", "Order updated successfully")
        
        except (sqlite3.Error, ValueError) as e:
            messagebox.showerror("Error", str(e))

    def delete_order(self):
        """Delete an existing order"""
        try:
            # Get selected order
            selected_item = self.order_tree.selection()
            if not selected_item:
                messagebox.showerror("Selection Error", "Please select an order to delete")
                return
            
            # Confirm deletion
            if messagebox.askyesno("Confirm", "Are you sure you want to delete this order?"):
                # Get order details for inventory adjustment
                order_details = self.order_tree.item(selected_item)['values']
                item_name = order_details[1]
                quantity = order_details[2]
                
                # Delete order
                self.cursor.execute("DELETE FROM orders WHERE id = ?", (self.current_order_id,))
                
                # Restore inventory
                self.cursor.execute('''
                    UPDATE inventory 
                    SET quantity = quantity + ? 
                    WHERE item_name = ?
                ''', (quantity, item_name))
                
                self.conn.commit()
                
                # Refresh displays
                self.refresh_order_display()
                self.clear_form()
                messagebox.showinfo("Success", "Order deleted successfully")
        
        except sqlite3.Error as e:
            messagebox.showerror("Error", str(e))

    def refresh_order_display(self):
        """Refresh the order treeview with current database contents"""
        # Clear existing items
        for i in self.order_tree.get_children():
            self.order_tree.delete(i)
        
        # Fetch and display orders
        try:
            self.cursor.execute("SELECT * FROM orders ORDER BY order_date DESC")
            for order in self.cursor.fetchall():
                # Format order data for display
                formatted_order = (
                    order[1],  # customer_name
                    order[2],  # item_name
                    order[3],  # quantity
                    f"${order[4]:.2f}",  # total_price
                    order[5],  # status
                    order[6]   # order_date
                )
                self.order_tree.insert("", "end", values=formatted_order)
        
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to retrieve orders: {e}")

    def on_order_select(self, event):
        """Handle order selection in the treeview"""
        selected_item = self.order_tree.selection()
        if selected_item:
            # Get selected order details
            order = self.order_tree.item(selected_item)['values']
            
            # Populate form fields
            self.fields[0][1].delete(0, tk.END)
            self.fields[0][1].insert(0, order[0])  # Customer Name
            
            self.fields[1][1].set(order[1])  # Item Name
            
            self.fields[2][1].delete(0, tk.END)
            self.fields[2][1].insert(0, str(order[2]))  # Quantity
            
            self.fields[3][1].delete(0, tk.END)
            self.fields[3][1].insert(0, order[3].replace('$', ''))  # Total Price
            
            self.fields[4][1].set(order[4])  # Status
            
            # Query to get the actual order ID
            self.cursor.execute('''
                SELECT id FROM orders 
                WHERE customer_name=? AND item_name=? AND quantity=? AND total_price=? AND status=?
            ''', (order[0], order[1], order[2], float(order[3].replace('$', '')), order[4]))
            
            result = self.cursor.fetchone()
            self.current_order_id = result[0] if result else None

    def update_order(self):
        """Update an existing order"""
        try:
            # Get selected order
            selected_item = self.order_tree.selection()
            if not selected_item:
                messagebox.showerror("Selection Error", "Please select an order to update")
                return
            
            # Ensure an order ID was found during selection
            if not self.current_order_id:
                messagebox.showerror("Selection Error", "Unable to locate the specific order")
                return
            
            # Collect updated details
            customer_name = self.fields[0][1].get()
            item_name = self.fields[1][1].get()
            quantity = int(self.fields[2][1].get())
            total_price = float(self.fields[3][1].get())
            status = self.fields[4][1].get()
            
            # Validate input
            if not all([customer_name, item_name, quantity, total_price, status]):
                messagebox.showerror("Input Error", "Please fill all fields")
                return
            
            # Get original order details to handle inventory adjustment
            self.cursor.execute('''
                SELECT item_name, quantity 
                FROM orders 
                WHERE id = ?
            ''', (self.current_order_id,))
            original_order = self.cursor.fetchone()
            
            if not original_order:
                messagebox.showerror("Error", "Original order not found")
                return
            
            original_item, original_quantity = original_order
            
            # Update order
            self.cursor.execute('''
                UPDATE orders 
                SET customer_name=?, item_name=?, quantity=?, 
                    total_price=?, status=? 
                WHERE id = ?
            ''', (customer_name, item_name, quantity, total_price, status, 
                self.current_order_id))
            
            # Adjust inventory
            if item_name != original_item or quantity != original_quantity:
                # Restore original item's quantity
                self.cursor.execute('''
                    UPDATE inventory 
                    SET quantity = quantity + ? 
                    WHERE item_name = ?
                ''', (original_quantity, original_item))
                
                # Reduce new item's quantity
                self.cursor.execute('''
                    UPDATE inventory 
                    SET quantity = quantity - ? 
                    WHERE item_name = ?
                ''', (quantity, item_name))
            
            self.conn.commit()
            
            # Refresh displays
            self.refresh_order_display()
            self.clear_form()
            messagebox.showinfo("Success", "Order updated successfully")
        
        except (sqlite3.Error, ValueError) as e:
            self.conn.rollback()
            messagebox.showerror("Error", str(e))

    def delete_order(self):
        """Delete an existing order"""
        try:
            # Get selected order
            selected_item = self.order_tree.selection()
            if not selected_item:
                messagebox.showerror("Selection Error", "Please select an order to delete")
                return
            
            # Ensure an order ID was found during selection
            if not self.current_order_id:
                messagebox.showerror("Selection Error", "Unable to locate the specific order")
                return
            
            # Confirm deletion
            if messagebox.askyesno("Confirm", "Are you sure you want to delete this order?"):
                # Get order details for inventory adjustment
                self.cursor.execute('''
                    SELECT item_name, quantity 
                    FROM orders 
                    WHERE id = ?
                ''', (self.current_order_id,))
                order_details = self.cursor.fetchone()
                
                if not order_details:
                    messagebox.showerror("Error", "Order details not found")
                    return
                
                item_name, quantity = order_details
                
                # Delete order
                self.cursor.execute("DELETE FROM orders WHERE id = ?", (self.current_order_id,))
                
                # Restore inventory
                self.cursor.execute('''
                    UPDATE inventory 
                    SET quantity = quantity + ? 
                    WHERE item_name = ?
                ''', (quantity, item_name))
                
                self.conn.commit()
                
                # Refresh displays
                self.refresh_order_display()
                self.clear_form()
                messagebox.showinfo("Success", "Order deleted successfully")
        
        except sqlite3.Error as e:
            self.conn.rollback()
            messagebox.showerror("Error", str(e))
            """Handle order selection in the treeview"""
            selected_item = self.order_tree.selection()
            if selected_item:
                # Get selected order details
                order = self.order_tree.item(selected_item)['values']
                
                # Populate form fields
                self.fields[0][1].delete(0, tk.END)
                self.fields[0][1].insert(0, order[0])  # Customer Name
                
                self.fields[1][1].set(order[1])  # Item Name
                
                self.fields[2][1].delete(0, tk.END)
                self.fields[2][1].insert(0, order[2])  # Quantity
                
                self.fields[3][1].delete(0, tk.END)
                self.fields[3][1].insert(0, order[3].replace('$', ''))  # Total Price
                
                self.fields[4][1].set(order[4])  # Status
                
                # Store current order ID for updates/deletion
                self.current_order_id = order[5] if len(order) > 5 else None

        def clear_form(self):
            """Clear all form fields"""
            for _, entry in self.fields:
                if isinstance(entry, tk.Entry):
                    entry.delete(0, tk.END)
                elif isinstance(entry, ttk.Combobox):
                    entry.set('')

        def return_home(self):
            """Return to the main window"""
            self.root.destroy()

        def __del__(self):
            """Ensure database connection is closed"""
            if hasattr(self, 'conn'):
                self.conn.close()

        def create_order_display(self, parent):
            # Treeview with modern styling
            columns = ("Customer Name", "Item Name", "Quantity", "Total Price", "Status", "Order Date")
            self.order_tree = ttk.Treeview(
                parent, 
                columns=columns,
                show='headings',
                selectmode='browse',
                style='Modern.Treeview'
            )
            
            # Configure treeview style
            style = ttk.Style()
            style.theme_use('clam')
            style.configure('Modern.Treeview', 
                            background=ModernStyle.BACKGROUND_COLOR, 
                            foreground='black',
                            rowheight=30,
                            font=(ModernStyle.FONT_FAMILY, 10))
            style.configure('Modern.Treeview.Heading', 
                            background=ModernStyle.PRIMARY_COLOR, 
                            foreground=ModernStyle.TEXT_COLOR,
                            font=(ModernStyle.FONT_FAMILY, 12, 'bold'))
            
            # Configure columns
            for col in columns:
                self.order_tree.heading(col, text=col, anchor='center')
                self.order_tree.column(col, anchor='center', width=120)
            
            # Scrollbar
            scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.order_tree.yview)
            self.order_tree.configure(yscrollcommand=scrollbar.set)
            
            # Layout
            self.order_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,10), pady=10)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
            
            # Bind selection event
            self.order_tree.bind('<<TreeviewSelect>>', self.on_order_select)
            
            # Refresh display
            self.refresh_order_display()

        def create_entry(self, parent, **kwargs):
            return tk.Entry(parent, **kwargs)

        def create_dropdown(self, parent, values):
            var = tk.StringVar()
            dropdown = ttk.Combobox(
                parent, 
                textvariable=var, 
                values=values,
                font=(ModernStyle.FONT_FAMILY, 12)
            )
            return dropdown

        def create_order_display(self, parent):
            """
            Create a treeview to display orders with modern styling and functionality
            
            Args:
                parent (tk.Frame): Parent container for the order display
            """
            # Define columns for the order display
            columns = ("Customer Name", "Item Name", "Quantity", "Total Price", "Status", "Order Date")
            
            # Create Treeview with modern styling
            self.order_tree = ttk.Treeview(
                parent, 
                columns=columns,
                show='headings',
                selectmode='browse',
                style='Modern.Treeview'
            )
            
            # Configure treeview style
            style = ttk.Style()
            style.theme_use('clam')
            style.configure('Modern.Treeview', 
                            background=ModernStyle.BACKGROUND_COLOR, 
                            foreground='black',
                            rowheight=30,
                            font=(ModernStyle.FONT_FAMILY, 10))
            style.configure('Modern.Treeview.Heading', 
                            background=ModernStyle.PRIMARY_COLOR, 
                            foreground=ModernStyle.TEXT_COLOR,
                            font=(ModernStyle.FONT_FAMILY, 12, 'bold'))
            
            # Configure column headings and width
            column_widths = {
                "Customer Name": 150,
                "Item Name": 150,
                "Quantity": 80,
                "Total Price": 100,
                "Status": 100,
                "Order Date": 150
            }
            
            for col in columns:
                self.order_tree.heading(col, text=col, anchor='center')
                self.order_tree.column(col, anchor='center', width=column_widths.get(col, 120))
            
            # Add vertical scrollbar
            scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.order_tree.yview)
            self.order_tree.configure(yscrollcommand=scrollbar.set)
            
            # Add horizontal scrollbar
            x_scrollbar = ttk.Scrollbar(parent, orient="horizontal", command=self.order_tree.xview)
            self.order_tree.configure(xscrollcommand=x_scrollbar.set)
            
            # Layout treeview and scrollbars
            self.order_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,10), pady=10)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
            x_scrollbar.pack(side=tk.BOTTOM, fill=tk.X, padx=10)
            
            # Bind selection event to populate form fields
            self.order_tree.bind('<<TreeviewSelect>>', self.on_order_select)
            
            # Optional: Add right-click context menu for additional actions
            context_menu = tk.Menu(self.root, tearoff=0)
            context_menu.add_command(label="View Details", command=self.show_order_details)
            context_menu.add_command(label="Export Order", command=self.export_order)
            
            def show_context_menu(event):
                """Show context menu on right-click"""
                # Select the row that was right-clicked
                iid = self.order_tree.identify_row(event.y)
                if iid:
                    self.order_tree.selection_set(iid)
                    context_menu.tk_popup(event.x_root, event.y_root)
            
            self.order_tree.bind("<Button-3>", show_context_menu)
            
            # Initial display refresh
            self.refresh_order_display()

        def show_order_details(self):
            """
            Display detailed information about the selected order
            """
            selected_item = self.order_tree.selection()
            if not selected_item:
                messagebox.showwarning("Selection Error", "Please select an order to view details.")
                return
            
            order = self.order_tree.item(selected_item)['values']
            details = f"""
        Order Details:
        --------------
        Customer: {order[0]}
        Item: {order[1]}
        Quantity: {order[2]}
        Total Price: {order[3]}
        Status: {order[4]}
        Order Date: {order[5]}
        """
            messagebox.showinfo("Order Details", details)

        def export_order(self):
            """
            Export selected order to a CSV file
            """
            selected_item = self.order_tree.selection()
            if not selected_item:
                messagebox.showwarning("Selection Error", "Please select an order to export.")
                return
            
            try:
                import csv
                from tkinter import filedialog
                
                order = self.order_tree.item(selected_item)['values']
                
                # Open file dialog to choose export location
                file_path = filedialog.asksaveasfilename(
                    defaultextension=".csv",
                    filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
                )
                
                if file_path:
                    with open(file_path, 'w', newline='') as csvfile:
                        writer = csv.writer(csvfile)
                        writer.writerow(["Customer Name", "Item Name", "Quantity", "Total Price", "Status", "Order Date"])
                        writer.writerow(order)
                    
                    messagebox.showinfo("Export Successful", f"Order exported to {file_path}")
            
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export order: {str(e)}")

def main():
    # Start with login page
    root = tk.Tk()
    LoginPage(root)
    root.mainloop()

if __name__ == "__main__":
    main()
    #Fix order diplay LAst