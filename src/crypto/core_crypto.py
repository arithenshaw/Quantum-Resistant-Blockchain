import os
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#import out hybrid cryptographic prmitives
from crypto.hybrid.hybrid_kem import HybridKEM
from crypto.hybrid.hybrid_signature import HybridSignature

class CoreCryptography:
    """
    Core Cryptographic operations for the quantum-resistant blockchain authentication
    """

    def __init__(self):
        self.kem = HybridKEM()
        self.signature = HybridSignature()

    def generate_user_keys(self, user_id=None, passphrase=None):
        """
        Generate a complete set of user keys for both encryption and signing.
        """
        # Generate encryption keypair
        encryption_private_key, encryption_public_key = self.kem.generate_keypair()

        # Generate signature keypair
        signature_private_key, signature_public_key = self.signature.generate_keypair()

        # Create key bundle
        key_bundle = {
            'user_id': user_id or str(os.urandom(16).hex()),
            'encryption': {
                'private': encryption_private_key,
                'public': encryption_public_key
            },
            'signature': {
                'private': signature_private_key,
                'public': signature_public_key
            }
        }

        # If a passpharse is provided, encrypt the private keys
        if passphrase:
            key_bundle = self.encrypt_key_bundle(key_bundle, passphrase)

        return key_bundle
    
    def encrypt_key_bundle(self, key_bundle, passphrase):
        """
        Encrypt the private keys in a key bundle using a passphrase.
        """

        #This is simplified - in a real-world scenario, you would use a more secure approach to serialize and encrypt the private keys
        # Derive a key from the passphrase
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(passphrase.encode())

        # we'd need more sophisticated serialization for the actual private keys
        #This is just an illustrative placeholder

        encrypted_bundle = {
            'user_id': key_bundle['user_id'],
            'encryption':{
                'private': 'encrypted', #would be actual encrypted data
                'public': key_bundle['encryption']['public']
            },
            'signature': {
                'private': 'encrypted', #would be actual encrypted data
                'public': key_bundle['signature']['public']
            },
            'encryption_metadata': {
                'salt': base64.b64encode(salt).decode(),
                'iterations': 100000,
                'algorithm': 'PBKDF2-SHA256+AES-GCM'
            }
        }

        return encrypted_bundle
    
    def create_authentication_challenge(self, user_public_key):
        """
        Create an authentication challenge for a user.
        """
        # Generate a random challenge
        challenge = os.urandom(32)

        # Encrypt the challenge with the user's public key
        encrypted_challenge = self.kem.encrypt_message(
            user_public_key['encryption']['public'],
            challenge
        )

        return {
            'challenge': challenge,
            'encrypted_challenge': encrypted_challenge
        }
    
    def verify_authentication_challenge(self, challenge, user_public_key, response):

        """
        Verify the user's response to an authentication challenge.
        """
        # Extract the signature from the response
        signature = response['signature']

        # verify the signature of the challenge
        is_valid = self.signature.verify(
            user_public_key['signature']['public'],
            challenge,
            signature
        )

        return is_valid
    
    def sign_blockchain_transaction(self, private_key, transaction_data):
        """
        Sign a blockchain transaction data using the user's signature key.
        """
        # Convert transaction data to a string if it's not already
        if isinstance(transaction_data, dict):
            transaction_string = json.dumps(transaction_data, sort_keys=True)
        else:
            transaction_string = str(transaction_data)

        # Sign the transaction
        signature = self.signature.sign(
            private_key,
            transaction_string
        )
        return signature
    
    def verify_blockchain_transaction(self, public_key, transaction_data, signature):
        """
        Verify a blockchain transaction signature
        """
        # Convert transaction data to a string if it's not already
        if isinstance(transaction_data, dict):
            transaction_string = json.dumps(transaction_data, sort_keys=True)
        else:
            transaction_string = str(transaction_data)

        # Verify the signature
        is_valid = self.signature.verify(
            public_key,
            transaction_string,
            signature
        )
        return is_valid
    
    def secure_key_exchange(self, initiator_private_key, recipient_public_key):
        """
        Perform a secure key exchange using the initiator's private key and the recipient's public key.
        """
        # Use the KEM to generate a shared secret
        # This could be used for secure communication or session keys
        ciphertext, shared_key = self.kem.encapsulate(recipient_public_key)

        #sign the ciphertext to authenticate the initiator
        ciphertext_signature = self.signature.sign(
            initiator_private_key,
            str(ciphertext)
        )

        #Bundle the exchange information
        exchange_package = {
            'ciphertext': ciphertext,
            'signature': ciphertext_signature
        }

        # Return the package to send and the shared key
        return exchange_package, shared_key

        