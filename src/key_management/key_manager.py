import os
import json
import time
import base64
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
from src.crypto.core_crypto import CoreCryptography

class KeyManager:
    """
    Key management system for quantum-resistant keys
    """
    
    def __init__(self, storage_dir=None, crypto=None):
        """
        Initialize the key manager
        
        Args:
            storage_dir: Directory to store encrypted keys
            crypto: CoreCryptography instance
        """
        self.storage_dir = storage_dir or Path("./keys")
        self.crypto = crypto or CoreCryptography()
        
        # Create storage directory if it doesn't exist
        os.makedirs(self.storage_dir, exist_ok=True)
    
    def generate_key_pair(self, user_id=None):
        """
        Generate a new hybrid key pair
        """
        return self.crypto.generate_user_keys(user_id)
    
    def encrypt_private_key(self, private_key, passphrase):
        """
        Encrypt a private key with a passphrase
        """
        # Generate a salt for the key derivation
        salt = os.urandom(16)
        
        # Derive an encryption key from the passphrase
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(passphrase.encode())
        
        # Use Fernet for encryption (uses AES-128-CBC with HMAC-SHA256 for authentication)
        key_base64 = base64.urlsafe_b64encode(key)
        f = Fernet(key_base64)
        
        # Serialize the private key to JSON
        # Note: In a real implementation, you'd need specialized serialization for the actual keys
        private_key_json = json.dumps({"dummy": "This is where the actual key serialization would happen"})
        
        # Encrypt the serialized private key
        encrypted_data = f.encrypt(private_key_json.encode())
        
        # Create metadata for decryption
        metadata = {
            "salt": base64.b64encode(salt).decode(),
            "iterations": 100000,
            "algorithm": "PBKDF2-SHA256+Fernet",
            "created_at": int(time.time())
        }
        
        # Return the encrypted key bundle
        return {
            "encrypted_data": base64.b64encode(encrypted_data).decode(),
            "metadata": metadata
        }
    
    def decrypt_private_key(self, encrypted_key_bundle, passphrase):
        """
        Decrypt a private key using a passphrase
        """
        # Extract the encryption metadata
        metadata = encrypted_key_bundle["metadata"]
        salt = base64.b64decode(metadata["salt"])
        iterations = metadata["iterations"]
        
        # Derive the encryption key from the passphrase
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        key = kdf.derive(passphrase.encode())
        
        # Use Fernet for decryption
        key_base64 = base64.urlsafe_b64encode(key)
        f = Fernet(key_base64)
        
        # Decrypt the data
        encrypted_data = base64.b64decode(encrypted_key_bundle["encrypted_data"])
        try:
            decrypted_data = f.decrypt(encrypted_data)
            # In a real implementation, you would deserialize and return the actual private key
            return json.loads(decrypted_data.decode())
        except Exception as e:
            # Failed decryption (likely wrong passphrase)
            raise ValueError(f"Failed to decrypt key: {str(e)}")
    
    def store_key(self, user_id, key_data, passphrase, key_type="user"):
        """
        Store an encrypted key bundle on disk
        
        Args:
            user_id: User identifier
            key_data: Key data to store
            passphrase: Passphrase for encryption
            key_type: Type of key (user, device, backup, etc.)
        """
        # Create a unique filename
        filename = f"{user_id}_{key_type}_{int(time.time())}.key"
        filepath = self.storage_dir / filename
        
        # Encrypt the key data
        if isinstance(key_data, dict) and ('private' in key_data or 'encryption' in key_data):
            # This is a private key bundle that needs encryption
            encrypted_data = self.encrypt_private_key(key_data, passphrase)
        else:
            # This is already encrypted or is a public key
            encrypted_data = key_data
            
        # Store metadata
        key_metadata = {
            "user_id": user_id,
            "key_type": key_type,
            "created_at": int(time.time()),
            "filename": filename
        }
        
        # Combine key data and metadata
        storage_bundle = {
            "metadata": key_metadata,
            "key_data": encrypted_data
        }
        
        # Write to file
        with open(filepath, 'w') as f:
            json.dump(storage_bundle, f)
            
        return filename
    
    def load_key(self, filename, passphrase=None):
        """
        Load a key from disk
        
        Args:
            filename: Name of the key file
            passphrase: Passphrase for decryption (if needed)
        """
        filepath = self.storage_dir / filename
        
        # Check if file exists
        if not filepath.exists():
            raise FileNotFoundError(f"Key file not found: {filename}")
            
        # Read the file
        with open(filepath, 'r') as f:
            storage_bundle = json.load(f)
            
        # Extract metadata
        metadata = storage_bundle["metadata"]
        key_data = storage_bundle["key_data"]
        
        # Decrypt if necessary and if passphrase provided
        if passphrase and isinstance(key_data, dict) and "encrypted_data" in key_data:
            try:
                decrypted_data = self.decrypt_private_key(key_data, passphrase)
                return {
                    "metadata": metadata,
                    "key_data": decrypted_data
                }
            except Exception as e:
                raise ValueError(f"Failed to decrypt key: {str(e)}")
        
        # Return as is (public key or already encrypted)
        return {
            "metadata": metadata,
            "key_data": key_data
        }
    
    def rotate_key(self, user_id, old_key_filename, old_passphrase, new_passphrase=None):
        """
        Rotate a user's key - generate a new key and store it securely
        
        Args:
            user_id: User identifier
            old_key_filename: Filename of the current key
            old_passphrase: Passphrase for the current key
            new_passphrase: Passphrase for the new key (if different)
        """
        # If no new passphrase is provided, use the old one
        if new_passphrase is None:
            new_passphrase = old_passphrase
            
        # Load the old key
        old_key_bundle = self.load_key(old_key_filename, old_passphrase)
        old_key_data = old_key_bundle["key_data"]
        
        # Generate a new key pair
        new_key_bundle = self.generate_key_pair(user_id)
        
        # Store the new key with the new passphrase
        new_filename = self.store_key(user_id, new_key_bundle, new_passphrase)
        
        # Return the old and new key bundles for blockchain update
        return {
            "old_key": old_key_data,
            "new_key": new_key_bundle,
            "new_filename": new_filename
        }
    
    def list_user_keys(self, user_id):
        """
        List all keys for a specific user
        """
        user_keys = []
        
        # Search for all keys matching the user_id
        for filepath in self.storage_dir.glob(f"{user_id}_*.key"):
            try:
                # Read the metadata without decrypting
                with open(filepath, 'r') as f:
                    storage_bundle = json.load(f)
                    
                # Extract metadata
                metadata = storage_bundle["metadata"]
                user_keys.append(metadata)
            except Exception:
                # Skip files that can't be parsed
                continue
                
        return user_keys
    
    def backup_key(self, key_filename, passphrase, backup_dir=None):
        """
        Create a backup of a key file
        """
        # Set backup directory
        if backup_dir is None:
            backup_dir = self.storage_dir / "backups"
            os.makedirs(backup_dir, exist_ok=True)
            
        # Load the key
        key_bundle = self.load_key(key_filename, passphrase)
        
        # Create a backup filename
        backup_filename = f"backup_{key_filename}_{int(time.time())}"
        backup_filepath = backup_dir / backup_filename
        
        # Store the backup
        with open(backup_filepath, 'w') as f:
            json.dump(key_bundle, f)
            
        return backup_filename
    
    def secure_wipe_key(self, key_filename):
        """
        Securely wipe a key from disk
        """
        filepath = self.storage_dir / key_filename
        
        # Check if file exists
        if not filepath.exists():
            raise FileNotFoundError(f"Key file not found: {key_filename}")
            
        # Overwrite the file with random data several times
        file_size = os.path.getsize(filepath)
        
        for _ in range(3):  # Overwrite 3 times
            with open(filepath, 'wb') as f:
                f.write(os.urandom(file_size))
                
        # Finally delete the file
        os.remove(filepath)