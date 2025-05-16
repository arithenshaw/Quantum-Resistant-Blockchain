import time
import json
import hashlib
from src.crypto.core_crypto import CoreCryptography

class TransactionFormat:
    """
    Defines the transaction format for quantum-resistant blockchain authentication
    """
    
    def __init__(self, crypto=None):
        self.crypto = crypto or CoreCryptography()
    
    def create_registration_transaction(self, user_id, public_key_bundle):
        """
        Create a transaction to register a new user's public keys on the blockchain
        """
        # Serialize the public keys
        serialized_encryption_key = self._serialize_key(public_key_bundle['encryption']['public'])
        serialized_signature_key = self._serialize_key(public_key_bundle['signature']['public'])
        
        # Create the transaction
        transaction = {
            'type': 'USER_REGISTER',
            'timestamp': int(time.time()),
            'version': '1.0',
            'user_id': user_id,
            'public_keys': {
                'encryption': serialized_encryption_key,
                'signature': serialized_signature_key
            },
            'metadata': {
                'algorithms': {
                    'encryption': 'HYBRID-ECC-KYBER',
                    'signature': 'HYBRID-ECDSA-DILITHIUM'
                },
                'registration_time': int(time.time())
            }
        }
        
        # Add transaction hash
        transaction['tx_hash'] = self._hash_transaction(transaction)
        
        return transaction
    
    def create_authentication_transaction(self, user_id, challenge_response, timestamp=None):
        """
        Create a transaction for an authentication event
        """
        # Create the transaction
        transaction = {
            'type': 'USER_AUTHENTICATE',
            'timestamp': timestamp or int(time.time()),
            'version': '1.0',
            'user_id': user_id,
            'auth_data': {
                'challenge_response': challenge_response,
                'auth_time': int(time.time())
            }
        }
        
        # Add transaction hash
        transaction['tx_hash'] = self._hash_transaction(transaction)
        
        return transaction
    
    def create_key_rotation_transaction(self, user_id, old_public_keys, new_public_keys, signature):
        """
        Create a transaction for key rotation (updating keys)
        """
        # Serialize the new public keys
        serialized_new_encryption_key = self._serialize_key(new_public_keys['encryption']['public'])
        serialized_new_signature_key = self._serialize_key(new_public_keys['signature']['public'])
        
        # Create the transaction
        transaction = {
            'type': 'KEY_ROTATION',
            'timestamp': int(time.time()),
            'version': '1.0',
            'user_id': user_id,
            'old_key_references': {
                'encryption': self._hash_key(old_public_keys['encryption']['public']),
                'signature': self._hash_key(old_public_keys['signature']['public'])
            },
            'new_public_keys': {
                'encryption': serialized_new_encryption_key,
                'signature': serialized_new_signature_key
            },
            'signature': signature,  # Signature using the old keys to authorize rotation
            'metadata': {
                'rotation_time': int(time.time()),
                'reason': 'SCHEDULED_ROTATION'  # Could also be COMPROMISED, ADMIN_REQUEST, etc.
            }
        }
        
        # Add transaction hash
        transaction['tx_hash'] = self._hash_transaction(transaction)
        
        return transaction
    
    def create_revocation_transaction(self, user_id, public_key_references, revocation_signature, admin_signature=None):
        """
        Create a transaction to revoke keys
        """
        # Create the transaction
        transaction = {
            'type': 'KEY_REVOCATION',
            'timestamp': int(time.time()),
            'version': '1.0',
            'user_id': user_id,
            'key_references': public_key_references,
            'revocation_signature': revocation_signature,
            'admin_signature': admin_signature,  # Optional admin override
            'metadata': {
                'revocation_time': int(time.time()),
                'reason': 'USER_REQUESTED'  # Could also be COMPROMISED, ADMIN_REVOKE, etc.
            }
        }
        
        # Add transaction hash
        transaction['tx_hash'] = self._hash_transaction(transaction)
        
        return transaction
    
    def sign_transaction(self, transaction, signature_private_key):
        """
        Sign a transaction with the user's signature key
        """
        # Create a copy without the signature field to sign
        tx_for_signing = transaction.copy()
        if 'signature' in tx_for_signing:
            del tx_for_signing['signature']
        
        # Sign the transaction
        signature = self.crypto.sign_blockchain_transaction(
            signature_private_key,
            tx_for_signing
        )
        
        # Create a signed copy
        signed_transaction = transaction.copy()
        signed_transaction['signature'] = signature
        
        return signed_transaction
    
    def verify_transaction_signature(self, transaction, public_key):
        """
        Verify a transaction's signature
        """
        if 'signature' not in transaction:
            return False
            
        signature = transaction['signature']
        
        # Create a copy without the signature field to verify
        tx_for_verification = transaction.copy()
        del tx_for_verification['signature']
        
        # Verify the signature
        return self.crypto.verify_blockchain_transaction(
            public_key,
            tx_for_verification,
            signature
        )
    
    def _serialize_key(self, key):
        """
        Serialize a public key for blockchain storage
        This is a placeholder - real implementation would depend on key format
        """
        # In a real implementation, this would properly serialize the keys based on their type
        if isinstance(key, dict):
            return {k: v.hex() if isinstance(v, bytes) else v for k, v in key.items()}
        else:
            return key.hex() if isinstance(key, bytes) else str(key)
    
    def _hash_key(self, key):
        """
        Create a hash reference for a key
        """
        serialized = json.dumps(self._serialize_key(key), sort_keys=True)
        return hashlib.sha256(serialized.encode()).hexdigest()
    
    def _hash_transaction(self, transaction):
        """
        Create a unique hash for a transaction
        """
        # Create a copy without the hash field
        tx_for_hashing = transaction.copy()
        if 'tx_hash' in tx_for_hashing:
            del tx_for_hashing['tx_hash']
        
        # Convert to a deterministic string representation
        tx_string = json.dumps(tx_for_hashing, sort_keys=True)
        
        # Hash the string
        return hashlib.sha256(tx_string.encode()).hexdigest()