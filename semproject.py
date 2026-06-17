"""
SecureVault Ultimate - Enterprise Grade Password Manager
--------------------------------------------------------
Author: Semester Project Student
Description: A highly secure, PyQt5-based password manager featuring AES-256 
encryption, PBKDF2 key derivation, built-in password generation, and audit logging.

Architecture Overview:
- CryptoManager: Handles all cryptographic operations (Fernet AES).
- DatabaseManager: Handles SQLite connections using context managers.
- AuditLogger: Tracks user actions for security compliance.
- PasswordGenerator: Configurable utility for creating strong passwords.
- SecureVaultApp: The main PyQt5 Graphical User Interface.
"""

import os
import sys
import sqlite3
import base64
import secrets
import string
import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLineEdit, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QMessageBox, QLabel, 
                             QProgressBar, QInputDialog, QTabWidget, QCheckBox, 
                             QSpinBox, QFormLayout, QDialog, QDialogButtonBox,
                             QAbstractItemView)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QIcon

# ==========================================
# 1. CONSTANTS & STYLESHEETS
# ==========================================
SALT = b'\x14\xef\xaa\x03\x12\x88\x19\x92\x01\x02\x03\x04\x05\x06\x07\x08'
ITERATIONS = 480000

STYLESHEET = """
    QMainWindow, QDialog { background-color: #121212; }
    QWidget { background-color: #121212; color: #E0E0E0; font-family: 'Segoe UI', sans-serif; font-size: 14px; }
    QTabWidget::pane { border: 1px solid #333; border-radius: 5px; }
    QTabBar::tab { background: #1E1E1E; color: #888; padding: 10px 20px; border-top-left-radius: 4px; border-top-right-radius: 4px; }
    QTabBar::tab:selected { background: #2D2D2D; color: #BB86FC; border-bottom: 2px solid #BB86FC; }
    QTableWidget { background-color: #1E1E1E; border: 1px solid #333; gridline-color: #333; border-radius: 8px; alternate-background-color: #252525; }
    QHeaderView::section { background-color: #2D2D2D; color: #BB86FC; padding: 8px; border: 1px solid #333; font-weight: bold; }
    QPushButton { background-color: #BB86FC; color: #000; border-radius: 4px; padding: 10px; font-weight: bold; }
    QPushButton:hover { background-color: #9965f4; }
    QPushButton:pressed { background-color: #7742d1; }
    QLineEdit, QSpinBox { background-color: #2D2D2D; border: 2px solid #333; border-radius: 5px; padding: 8px; color: white; }
    QLineEdit:focus, QSpinBox:focus { border: 2px solid #BB86FC; }
    QProgressBar { border: 2px solid #333; border-radius: 5px; text-align: center; height: 12px; }
    QProgressBar::chunk { background-color: #03DAC6; }
    QCheckBox { spacing: 8px; }
    QCheckBox::indicator { width: 18px; height: 18px; }
"""

# ==========================================
# 2. CORE ENCRYPTION MODULE
# ==========================================
class CryptoManager:
    """Handles PBKDF2 key derivation and AES encryption/decryption."""
    
    def __init__(self, master_password: str):
        """Initializes the encryption engine with the user's master password."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            iterations=ITERATIONS,
        )
        self.key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        self.fernet = Fernet(self.key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypts a plaintext string and returns the ciphertext token."""
        try:
            return self.fernet.encrypt(plaintext.encode()).decode()
        except Exception as e:
            raise RuntimeError(f"Encryption failed: {str(e)}")

    def decrypt(self, ciphertext: str) -> str:
        """Decrypts a ciphertext token back to plaintext."""
        try:
            return self.fernet.decrypt(ciphertext.encode()).decode()
        except InvalidToken:
            raise ValueError("Invalid Master Password or Corrupted Data")
        except Exception as e:
            raise RuntimeError(f"Decryption failed: {str(e)}")

# ==========================================
# 3. DATABASE & AUDIT LOGGING MODULES
# ==========================================
class DatabaseManager:
    """Handles all SQLite3 database operations with context management."""
    
    def __init__(self, db_name="secure_vault.db"):
        self.db_name = db_name
        self.init_db()

    def init_db(self):
        """Creates the necessary tables if they do not exist."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            # Passwords Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    site TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            # Audit Log Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL
                )
            ''')
            conn.commit()

    def execute_query(self, query: str, params: tuple = ()):
        """Executes a write query safely."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()

    def fetch_all(self, query: str, params: tuple = ()) -> list:
        """Executes a read query and returns all results."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()

class AuditLogger:
    """Manages system audit logs for security tracking."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def log(self, action: str, details: str):
        """Records an action in the database."""
        query = "INSERT INTO audit_logs (action, details) VALUES (?, ?)"
        self.db.execute_query(query, (action, details))

    def get_logs(self, limit: int = 50) -> list:
        """Retrieves the most recent audit logs."""
        query = "SELECT timestamp, action, details FROM audit_logs ORDER BY timestamp DESC LIMIT ?"
        return self.db.fetch_all(query, (limit,))

# ==========================================
# 4. UTILITIES MODULE
# ==========================================
class PasswordGenerator:
    """Utility class to generate cryptographically secure passwords."""
    
    @staticmethod
    def generate(length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True) -> str:
        """Generates a password based on specified constraints."""
        character_pool = ""
        if use_upper: character_pool += string.ascii_uppercase
        if use_lower: character_pool += string.ascii_lowercase
        if use_digits: character_pool += string.digits
        if use_symbols: character_pool += "!@#$%^&*()-_=+[]{}|;:,.<>?"
        
        if not character_pool:
            raise ValueError("At least one character type must be selected.")
            
        return "".join(secrets.choice(character_pool) for _ in range(length))

    @staticmethod
    def evaluate_strength(password: str) -> int:
        """Returns a strength score from 0 to 100 based on complexity."""
        score = 0
        if not password: return score
        if len(password) >= 8: score += 20
        if len(password) >= 12: score += 20
        if any(c.isupper() for c in password): score += 15
        if any(c.islower() for c in password): score += 15
        if any(c.isdigit() for c in password): score += 15
        if any(c in string.punctuation for c in password): score += 15
        return min(score, 100)

# ==========================================
# 5. GRAPHICAL USER INTERFACE
# ==========================================
class LoginDialog(QDialog):
    """Initial authentication dialog for the master password."""
    
    def __init__(self):
        super().__init__()
        self.master_pwd = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("SecureVault Ultimate - Login")
        self.setFixedSize(400, 200)
        self.setStyleSheet(STYLESHEET)
        
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("🔐 Enter Master Vault Key")
        title.setFont(QFont('Segoe UI', 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
        
        # Input
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.Password)
        self.pwd_input.setPlaceholderText("Master Password...")
        layout.addWidget(self.pwd_input)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.authenticate)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.setLayout(layout)

    def authenticate(self):
        if len(self.pwd_input.text()) < 1:
            QMessageBox.warning(self, "Error", "Master password cannot be empty.")
            return
        self.master_pwd = self.pwd_input.text()
        self.accept()

class SecureVaultApp(QMainWindow):
    """The main application window featuring tabs for Vault, Generator, and Logs."""
    
    def __init__(self, crypto_manager: CryptoManager, db_manager: DatabaseManager, logger: AuditLogger):
        super().__init__()
        self.crypto = crypto_manager
        self.db = db_manager
        self.logger = logger
        
        self.logger.log("SYSTEM", "SecureVault Application Started & Authenticated")
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("SecureVault Ultimate")
        self.setMinimumSize(900, 600)
        self.setStyleSheet(STYLESHEET)

        # Main Tab Widget
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Setup Tabs
        self.setup_vault_tab()
        self.setup_generator_tab()
        self.setup_audit_tab()

    def setup_vault_tab(self):
        """Sets up the primary password management interface."""
        vault_widget = QWidget()
        layout = QVBoxLayout()

        # Header Area
        header_layout = QHBoxLayout()
        title = QLabel("🛡️ Password Vault")
        title.setFont(QFont('Segoe UI', 20, QFont.Bold))
        header_layout.addWidget(title)
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.setFixedWidth(120)
        refresh_btn.clicked.connect(self.load_vault_data)
        header_layout.addWidget(refresh_btn, alignment=Qt.AlignRight)
        layout.addLayout(header_layout)

        # Data Table
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["ID", "Website", "Username", "Encrypted Ciphertext"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table)

        # Data Entry Area
        entry_layout = QHBoxLayout()
        self.site_input = QLineEdit(); self.site_input.setPlaceholderText("Website URL / App Name")
        self.user_input = QLineEdit(); self.user_input.setPlaceholderText("Username / Email")
        self.pwd_input = QLineEdit(); self.pwd_input.setPlaceholderText("Password")
        self.pwd_input.setEchoMode(QLineEdit.Password)
        self.pwd_input.textChanged.connect(self.update_strength_meter)
        
        entry_layout.addWidget(self.site_input)
        entry_layout.addWidget(self.user_input)
        entry_layout.addWidget(self.pwd_input)
        layout.addLayout(entry_layout)

        # Visual Feedback
        self.strength_bar = QProgressBar()
        self.strength_bar.setValue(0)
        self.strength_bar.setFormat("Password Strength: %p%")
        layout.addWidget(self.strength_bar)

        # Action Buttons
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("💾 Save to Vault")
        add_btn.clicked.connect(self.add_entry)
        
        decrypt_btn = QPushButton("🔓 Decrypt & Copy")
        decrypt_btn.clicked.connect(self.copy_to_clipboard)
        
        delete_btn = QPushButton("🗑️ Delete Selected")
        delete_btn.clicked.connect(self.delete_entry)
        delete_btn.setStyleSheet("background-color: #CF6679; color: black;") # Red distinct color
        
        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(decrypt_btn)
        btn_layout.addWidget(delete_btn)
        layout.addLayout(btn_layout)

        vault_widget.setLayout(layout)
        self.tabs.addTab(vault_widget, "📂 My Vault")
        self.load_vault_data()

    def setup_generator_tab(self):
        """Sets up the robust password generator interface."""
        gen_widget = QWidget()
        layout = QVBoxLayout()
        
        title = QLabel("⚙️ Secure Password Generator")
        title.setFont(QFont('Segoe UI', 18, QFont.Bold))
        layout.addWidget(title)
        
        form = QFormLayout()
        
        self.len_spinbox = QSpinBox()
        self.len_spinbox.setRange(8, 64)
        self.len_spinbox.setValue(16)
        form.addRow("Password Length:", self.len_spinbox)
        
        self.chk_upper = QCheckBox("Include Uppercase (A-Z)")
        self.chk_upper.setChecked(True)
        form.addRow("", self.chk_upper)
        
        self.chk_lower = QCheckBox("Include Lowercase (a-z)")
        self.chk_lower.setChecked(True)
        form.addRow("", self.chk_lower)
        
        self.chk_digits = QCheckBox("Include Digits (0-9)")
        self.chk_digits.setChecked(True)
        form.addRow("", self.chk_digits)
        
        self.chk_symbols = QCheckBox("Include Symbols (!@#$...)")
        self.chk_symbols.setChecked(True)
        form.addRow("", self.chk_symbols)
        
        layout.addLayout(form)
        
        self.gen_result = QLineEdit()
        self.gen_result.setReadOnly(True)
        self.gen_result.setFont(QFont('Courier', 14))
        layout.addWidget(self.gen_result)
        
        btn_layout = QHBoxLayout()
        gen_btn = QPushButton("⚡ Generate Password")
        gen_btn.clicked.connect(self.execute_generation)
        copy_gen_btn = QPushButton("📋 Copy Generated")
        copy_gen_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.gen_result.text()))
        
        btn_layout.addWidget(gen_btn)
        btn_layout.addWidget(copy_gen_btn)
        layout.addLayout(btn_layout)
        layout.addStretch()

        gen_widget.setLayout(layout)
        self.tabs.addTab(gen_widget, "🔧 Generator")

    def setup_audit_tab(self):
        """Sets up the security audit log viewing interface."""
        audit_widget = QWidget()
        layout = QVBoxLayout()
        
        title = QLabel("📜 Security Audit Logs")
        title.setFont(QFont('Segoe UI', 18, QFont.Bold))
        layout.addWidget(title)
        
        self.audit_table = QTableWidget(0, 3)
        self.audit_table.setHorizontalHeaderLabels(["Timestamp", "Action", "Details"])
        self.audit_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.audit_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.audit_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.audit_table)
        
        refresh_logs_btn = QPushButton("🔄 Refresh Logs")
        refresh_logs_btn.clicked.connect(self.load_audit_logs)
        layout.addWidget(refresh_logs_btn)
        
        audit_widget.setLayout(layout)
        self.tabs.addTab(audit_widget, "📊 Audit Logs")
        self.load_audit_logs()

    # --- VAULT LOGIC ---
    def update_strength_meter(self):
        """Dynamically updates the progress bar based on input password strength."""
        score = PasswordGenerator.evaluate_strength(self.pwd_input.text())
        self.strength_bar.setValue(score)
        
        # Color coding
        if score < 40: self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #CF6679; }") # Red
        elif score < 80: self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #FFB300; }") # Yellow
        else: self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #03DAC6; }") # Green

    def load_vault_data(self):
        """Fetches data from the database and populates the table."""
        self.table.setRowCount(0)
        records = self.db.fetch_all("SELECT id, site, username, password FROM accounts")
        for row_idx, row_data in enumerate(records):
            self.table.insertRow(row_idx)
            for col_idx, data in enumerate(row_data):
                item = QTableWidgetItem(str(data))
                item.setTextAlignment(Qt.AlignCenter if col_idx == 0 else Qt.AlignLeft | Qt.AlignVCenter)
                self.table.setItem(row_idx, col_idx, item)

    def add_entry(self):
        """Encrypts user input and saves to the database."""
        site = self.site_input.text().strip()
        user = self.user_input.text().strip()
        pwd = self.pwd_input.text()
        
        if not (site and user and pwd):
            QMessageBox.warning(self, "Validation Error", "All fields must be filled out.")
            return

        try:
            encrypted_pwd = self.crypto.encrypt(pwd)
            self.db.execute_query(
                "INSERT INTO accounts (site, username, password) VALUES (?, ?, ?)", 
                (site, user, encrypted_pwd)
            )
            self.logger.log("VAULT_ADD", f"Added credentials for site: {site}")
            self.load_vault_data()
            self.load_audit_logs()
            
            # Clear inputs
            self.site_input.clear()
            self.user_input.clear()
            self.pwd_input.clear()
            self.strength_bar.setValue(0)
            
            QMessageBox.information(self, "Success", "Credentials securely encrypted and saved.")
        except Exception as e:
            QMessageBox.critical(self, "Cryptography Error", f"Failed to save data: {str(e)}")

    def delete_entry(self):
        """Removes the selected entry from the database."""
        current_row = self.table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Selection Error", "Please select a row to delete.")
            return
            
        record_id = self.table.item(current_row, 0).text()
        site_name = self.table.item(current_row, 1).text()
        
        confirm = QMessageBox.question(self, "Confirm Deletion", 
                                       f"Are you sure you want to delete credentials for {site_name}?",
                                       QMessageBox.Yes | QMessageBox.No)
        
        if confirm == QMessageBox.Yes:
            self.db.execute_query("DELETE FROM accounts WHERE id = ?", (record_id,))
            self.logger.log("VAULT_DELETE", f"Deleted credentials for site: {site_name}")
            self.load_vault_data()
            self.load_audit_logs()

    def copy_to_clipboard(self):
        """Decrypts the selected password and copies it temporarily."""
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Selection Error", "Please select a row to decrypt.")
            return
            
        site_name = self.table.item(row, 1).text()
        encrypted_pwd = self.table.item(row, 3).text()
        
        try:
            decrypted_pwd = self.crypto.decrypt(encrypted_pwd)
            QApplication.clipboard().setText(decrypted_pwd)
            
            self.logger.log("VAULT_DECRYPT", f"Decrypted and copied password for site: {site_name}")
            self.load_audit_logs()
            
            QMessageBox.information(self, "Security Notice", 
                                    "Password decrypted and copied to clipboard!\n\n"
                                    "Clipboard will automatically clear in 15 seconds to prevent memory scraping.")
            
            # Auto-clear clipboard for security
            QTimer.singleShot(15000, lambda: QApplication.clipboard().clear())
            
        except ValueError:
            QMessageBox.critical(self, "Decryption Error", "Failed to decrypt. Master password may be incorrect.")
            self.logger.log("SECURITY_ALERT", f"Failed decryption attempt for site: {site_name}")

    # --- GENERATOR & AUDIT LOGIC ---
    def execute_generation(self):
        """Generates a password based on UI constraints."""
        try:
            pwd = PasswordGenerator.generate(
                length=self.len_spinbox.value(),
                use_upper=self.chk_upper.isChecked(),
                use_lower=self.chk_lower.isChecked(),
                use_digits=self.chk_digits.isChecked(),
                use_symbols=self.chk_symbols.isChecked()
            )
            self.gen_result.setText(pwd)
            self.logger.log("TOOL_USAGE", "Generated a new secure password.")
            self.load_audit_logs()
        except ValueError as e:
            QMessageBox.warning(self, "Configuration Error", str(e))

    def load_audit_logs(self):
        """Fetches audit logs and populates the audit table."""
        self.audit_table.setRowCount(0)
        logs = self.logger.get_logs()
        for row_idx, row_data in enumerate(logs):
            self.audit_table.insertRow(row_idx)
            for col_idx, data in enumerate(row_data):
                self.audit_table.setItem(row_idx, col_idx, QTableWidgetItem(str(data)))

# ==========================================
# 6. APPLICATION ENTRY POINT
# ==========================================
def main():
    """Main application loop and bootstrapping."""
    app = QApplication(sys.argv)
    
    # 1. Initialize Database and Logger
    db_manager = DatabaseManager()
    logger = AuditLogger(db_manager)
    
    # 2. Master Password Authentication
    login = LoginDialog()
    if login.exec_() == QDialog.Accepted:
        try:
            # 3. Initialize Crypto Engine
            crypto_manager = CryptoManager(login.master_pwd)
            
            # 4. Launch Main Window
            window = SecureVaultApp(crypto_manager, db_manager, logger)
            window.show()
            sys.exit(app.exec_())
        except Exception as e:
            QMessageBox.critical(None, "Fatal Error", f"Application failed to initialize:\n{str(e)}")
            logger.log("SYSTEM_ERROR", f"Initialization failed: {str(e)}")
    else:
        logger.log("SYSTEM", "User cancelled login sequence.")
        sys.exit(0)

if __name__ == "__main__":
    main()





    