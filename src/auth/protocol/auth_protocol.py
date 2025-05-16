import os
import time
import json
import hashlib
import base64
from src.crypto.core_crypto import CoreCryptography
from src.blockchain.transaction import TransactionFormat

class AuthenticationProtocol:
    """
    Implementation of the quantum-resistant authentication protocol
    """
    
    def __init__(self, crypto=None, transaction_format=None):
        self.crypto = crypto or CoreCryptography()
        self.transaction_format = transaction_format or TransactionFormat(self.crypto)
        self.active_challenges = {}  # In production, use a proper database
    
    def generate_challenge(self, user_id, public_key):
        """
        Generate a challenge for user authentication
        """
        # Create a unique challenge ID
        challenge_id = hashlib.sha256(os.urandom(32)).hexdigest()
        
        # Generate the challenge
        challenge_data = self.crypto.create_authentication_challenge(public_key)
        
        # Store the challenge for later verification
        self.active_challenges[challenge_id] = {
            'user_id': user_id,
            'challenge': challenge_data['challenge'],
            'timestamp': time.time(),
            'used': False,
            'expires_at': time.time() + 300  # 5 minutes expiration
        }
        
        # Return the challenge ID and encrypted challenge to send to the user
        return {
            'challenge_id': challenge_id,
            'encrypted_challenge': challenge_data['encrypted_challenge']
        }
    
    def verify_challenge_response(self, challenge_id, response_data, public_key):
        """
        Verify a user's response to an authentication challenge
        """
        # Check if the challenge exists and is not expired
        if challenge_id not in self.active_challenges:
            return False, "Challenge not found"
            
        challenge_info = self.active_challenges[challenge_id]
        
        # Check if challenge is expired
        if challenge_info['expires_at'] < time.time():
            return False, "Challenge expired"
            
        # Check if challenge was already used
        if challenge_info['used']:
            return False, "Challenge already used"
            
        # Mark the challenge as used
        challenge_info['used'] = True
        
        # Extract the challenge
        challenge = challenge_info['challenge']
        
        # Verify the response
        is_valid = self.crypto.verify_authentication_response(
            challenge,
            public_key,
            response_data
        )
        
        if not is_valid:
            return False, "Invalid signature"
            
        # If valid, create a blockchain transaction to record this authentication
        transaction = self.transaction_format.create_authentication_transaction(
            challenge_info['user_id'],
            response_data,
            int(time.time())
        )
        
        # In a real implementation, we would now broadcast this transaction to the blockchain
        
        return True, transaction
    
    def authenticate_user(self, user_id, user_private_key, challenge_data):
        """
        Authenticate a user by responding to a challenge
        This would typically run on the user's client
        """
        # Extract the encrypted challenge
        encrypted_challenge = challenge_data['encrypted_challenge']
        
        # Decrypt the challenge
        challenge = self.crypto.kem.decrypt_message(
            user_private_key['encryption'],
            encrypted_challenge
        )
        
        # Sign the challenge with the user's signature key
        signature = self.crypto.signature.sign(
            user_private_key['signature'],
            challenge
        )
        
        # Create the response
        response = {
            'signature': signature,
            'timestamp': int(time.time())
        }
        
        return response
    
    def register_user(self, user_id=None, passphrase=None):
        """
        Register a new user
        Returns the key bundle and transaction for blockchain registration
        """
        # Generate user keys
        key_bundle = self.crypto.generate_user_keys(user_id, passphrase)
        
        # Create a blockchain transaction for registration
        transaction = self.transaction_format.create_registration_transaction(
            key_bundle['user_id'],
            {
                'encryption': {'public': key_bundle['encryption']['public']},
                'signature': {'public': key_bundle['signature']['public']}
            }
        )
        
        # In a real implementation, we would now broadcast this transaction to the blockchain
        
        return key_bundle, transaction
    
    def rotate_keys(self, user_id, old_keys, new_keys=None):
        """
        Rotate a user's keys to new ones
        """
        # Generate new keys if not provided
        if new_keys is None:
            _, new_public_keys = self.crypto.generate_user_keys()
            new_keys = {
                'encryption': {'public': new_public_keys['encryption']['public']},
                'signature': {'public': new_public_keys['signature']['public']}
            }
        
        # Sign the key rotation with the old keys
        rotation_data = {
            'user_id': user_id,
            'old_keys': {
                'encryption': self.crypto._hash_key(old_keys['encryption']['public']),
                'signature': self.crypto._hash_key(old_keys['signature']['public'])
            },
            'new_keys': {
                'encryption': self.crypto._hash_key(new_keys['encryption']['public']),
                'signature': self.crypto._hash_key(new_keys['signature']['public'])
            },
            'timestamp': int(time.time())
        }
        
        # Sign the rotation data
        signature = self.crypto.sign_blockchain_transaction(
            old_keys['signature']['private'],
            rotation_data
        )
        
        # Create a blockchain transaction for key rotation
        transaction = self.transaction_format.create_key_rotation_transaction(
            user_id,
            old_keys,
            new_keys,
            signature
        )
        
        # In a real implementation, we would now broadcast this transaction to the blockchain
        
        return new_keys, transaction
    
    def revoke_keys(self, user_id, keys, reason="USER_REQUESTED"):
        """
        Revoke a user's keys
        """
        # Create key references
        key_references = {
            'encryption': self.crypto._hash_key(keys['encryption']['public']),
            'signature': self.crypto._hash_key(keys['signature']['public'])
        }
        
        # Sign the revocation with the user's private key
        revocation_data = {
            'user_id': user_id,
            'key_references': key_references,
            'reason': reason,
            'timestamp': int(time.time())
        }
        
        # Sign the revocation data
        signature = self.crypto.sign_blockchain_transaction(
            keys['signature']['private'],
            revocation_data
        )
        
        # Create a blockchain transaction for key revocation
        transaction = self.transaction_format.create_revocation_transaction(
            user_id,
            key_references,
            signature
        )
        
        # In a real implementation, we would now broadcast this transaction to the blockchain
        
        return transaction