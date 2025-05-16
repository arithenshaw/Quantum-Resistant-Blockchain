import json
import time
import hashlib
from web3 import Web3
from src.crypto.core_crypto import CoreCryptography

class BlockchainVerifier:
    """
    Verification utilities for the blockchain-based authentication
    """
    
    def __init__(self, web3_provider=None, contract_client=None, crypto=None):
        """
        Initialize the blockchain verifier
        
        Args:
            web3_provider: Web3 provider URL
            contract_client: BlockchainClient instance
            crypto: CoreCryptography instance
        """
        # Connect to Web3 provider if needed
        if web3_provider is not None:
            self.w3 = Web3(Web3.HTTPProvider(web3_provider))
        elif contract_client is not None:
            self.w3 = contract_client.w3
        else:
            # Default to local node
            self.w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))
            
        # Store references
        self.contract_client = contract_client
        self.crypto = crypto or CoreCryptography()
    
    def verify_transaction(self, tx_hash):
        """
        Verify a transaction on the blockchain
        
        Args:
            tx_hash: Transaction hash to verify
        """
        # Convert hash to bytes if it's a hex string
        if isinstance(tx_hash, str):
            if tx_hash.startswith('0x'):
                tx_hash = tx_hash[2:]
            tx_hash = bytes.fromhex(tx_hash)
            
        try:
            # Get transaction receipt
            receipt = self.w3.eth.get_transaction_receipt(tx_hash)
            
            # Check if transaction was successful
            if receipt.status == 1:
                # Get transaction details
                tx = self.w3.eth.get_transaction(tx_hash)
                
                return {
                    "status": "confirmed",
                    "block_number": receipt.blockNumber,
                    "block_hash": receipt.blockHash.hex(),
                    "from_address": receipt.from_address,
                    "to_address": receipt.to,
                    "gas_used": receipt.gasUsed,
                    "timestamp": self._get_block_timestamp(receipt.blockNumber),
                    "transaction": tx
                }
            else:
                return {
                    "status": "failed",
                    "block_number": receipt.blockNumber,
                    "gas_used": receipt.gasUsed
                }
                
        except Exception as e:
            # Transaction not found or other error
            return {
                "status": "not_found",
                "error": str(e)
            }
    
    def verify_user_registration(self, user_id, expected_keys=None):
        """
        Verify a user's registration on the blockchain
        
        Args:
            user_id: User identifier
            expected_keys: Expected public keys to verify against (optional)
        """
        if self.contract_client is None:
            raise ValueError("Contract client not initialized")
            
        # Check if user exists
        user_exists = self.contract_client.user_exists(user_id)
        
        if not user_exists:
            return {
                "status": "not_registered",
                "message": f"User {user_id} not found on the blockchain"
            }
            
        # Get the user's keys
        user_keys = self.contract_client.get_user_keys(user_id)
        
        # If expected keys are provided, verify they match
        if expected_keys is not None:
            # Compare encryption keys
            if self._compare_keys(user_keys["encryption_key"], expected_keys["encryption"]) is False:
                return {
                    "status": "key_mismatch",
                    "message": "Encryption key mismatch",
                    "blockchain_key": user_keys["encryption_key"]
                }
                
            # Compare signature keys
            if self._compare_keys(user_keys["signature_key"], expected_keys["signature"]) is False:
                return {
                    "status": "key_mismatch",
                    "message": "Signature key mismatch",
                    "blockchain_key": user_keys["signature_key"]
                }
        
        # Check if keys are active
        if not user_keys["is_active"]:
            return {
                "status": "keys_revoked",
                "message": "User keys are revoked",
                "keys": user_keys
            }
            
        # Get the last authentication time
        last_auth = self.contract_client.get_last_authentication(user_id)
        
        # Return the verification result
        return {
            "status": "verified",
            "message": "User is registered with active keys",
            "keys": user_keys,
            "last_authentication": last_auth
        }
    
    def verify_signature(self, message, signature, public_key):
        """
        Verify a hybrid signature
        
        Args:
            message: Message that was signed
            signature: Hybrid signature to verify
            public_key: Public key to use for verification
        """
        # Use the CoreCryptography module to verify the signature
        is_valid = self.crypto.verify_blockchain_transaction(
            public_key,
            message,
            signature
        )
        
        return {
            "status": "valid" if is_valid else "invalid",
            "message": "Signature verification successful" if is_valid else "Signature verification failed"
        }
    
    def verify_authentication_event(self, user_id, auth_time, max_age=None):
        """
        Verify a user's authentication status
        
        Args:
            user_id: User identifier
            auth_time: Authentication timestamp to verify
            max_age: Maximum allowed age in seconds (optional)
        """
        if self.contract_client is None:
            raise ValueError("Contract client not initialized")
            
        # Check if user exists
        user_exists = self.contract_client.user_exists(user_id)
        
        if not user_exists:
            return {
                "status": "not_registered",
                "message": f"User {user_id} not found on the blockchain"
            }
            
        # Get the last authentication time
        last_auth = self.contract_client.get_last_authentication(user_id)
        
        # Check if the authentication timestamp matches
        if auth_time != last_auth:
            return {
                "status": "auth_mismatch",
                "message": "Authentication timestamp does not match blockchain record",
                "expected": auth_time,
                "actual": last_auth
            }
            
        # If max age is provided, check if the authentication is still valid
        if max_age is not None:
            current_time = int(time.time())
            age = current_time - last_auth
            
            if age > max_age:
                return {
                    "status": "expired",
                    "message": f"Authentication expired (age: {age}s, max: {max_age}s)",
                    "auth_time": last_auth,
                    "current_time": current_time,
                    "age": age
                }
        
        # Return the verification result
        return {
            "status": "valid",
            "message": "Authentication is valid",
            "auth_time": last_auth
        }
    
    def _get_block_timestamp(self, block_number):
        """
        Get the timestamp of a block
        
        Args:
            block_number: Block number
        """
        block = self.w3.eth.get_block(block_number)
        return block.timestamp
    
    def _compare_keys(self, blockchain_key, expected_key):
        """
        Compare keys from blockchain with expected keys
        
        Args:
            blockchain_key: Key from the blockchain
            expected_key: Expected key
        """
        # Convert the blockchain key to a comparable format
        if isinstance(blockchain_key, str):
            try:
                blockchain_key = json.loads(blockchain_key)
            except json.JSONDecodeError:
                pass
                
        # Convert the expected key to a comparable format
        expected_key_comparable = self._serialize_key(expected_key)
        
        # Compare the keys
        if isinstance(blockchain_key, dict) and isinstance(expected_key_comparable, dict):
            # Compare dictionaries
            for key in blockchain_key:
                if key not in expected_key_comparable:
                    return False
                if blockchain_key[key] != expected_key_comparable[key]:
                    return False
            return True
        else:
            # Compare primitive values
            return blockchain_key == expected_key_comparable
    
    def _serialize_key(self, key):
        """
        Serialize a key for comparison
        
        Args:
            key: Key to serialize
        """
        if isinstance(key, dict):
            return {k: v.hex() if isinstance(v, bytes) else v for k, v in key.items()}
        else:
            return key.hex() if isinstance(key, bytes) else str(key)