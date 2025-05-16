import json
import time
from web3 import Web3
from web3.middleware import geth_poa_middleware
from eth_account import Account
from src.crypto.core_crypto import CoreCryptography

class BlockchainClient:
    """
    Client to interact with the blockchain smart contracts
    """
    
    def __init__(self, web3_provider=None, contract_address=None, contract_abi=None, crypto=None):
        """
        Initialize the blockchain client
        
        Args:
            web3_provider: Web3 provider URL (e.g. 'http://localhost:8545')
            contract_address: Address of the deployed smart contract
            contract_abi: ABI of the smart contract
            crypto: CoreCryptography instance
        """
        # Connect to Web3 provider
        if web3_provider is None:
            # Default to local node
            web3_provider = 'http://localhost:8545'
            
        self.w3 = Web3(Web3.HTTPProvider(web3_provider))
        
        # Add middleware for PoA chains like test networks
        self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        
        # Store contract details
        self.contract_address = contract_address
        self.contract_abi = contract_abi
        
        # Initialize the cryptography module
        self.crypto = crypto or CoreCryptography()
        
        # Initialize contract instance if address and ABI are provided
        self.contract = None
        if contract_address and contract_abi:
            self.init_contract(contract_address, contract_abi)
            
    def init_contract(self, contract_address, contract_abi):
        """
        Initialize the contract instance
        """
        # Convert address to checksum address
        self.contract_address = self.w3.to_checksum_address(contract_address)
        self.contract_abi = contract_abi
        
        # Create contract instance
        self.contract = self.w3.eth.contract(
            address=self.contract_address,
            abi=self.contract_abi
        )
        
        return self.contract
    
    def load_contract_from_file(self, abi_file, contract_address):
        """
        Load contract ABI from a file
        """
        with open(abi_file, 'r') as f:
            contract_abi = json.load(f)
            
        return self.init_contract(contract_address, contract_abi)
    
    def register_user(self, eth_private_key, user_id, encryption_public_key, signature_public_key):
        """
        Register a new user on the blockchain
        
        Args:
            eth_private_key: Ethereum private key for transaction signing
            user_id: User identifier
            encryption_public_key: User's encryption public key (hybrid)
            signature_public_key: User's signature public key (hybrid)
        """
        # Check if contract is initialized
        if self.contract is None:
            raise ValueError("Contract not initialized")
            
        # Create Ethereum account from private key
        account = Account.from_key(eth_private_key)
        
        # Serialize the public keys
        encrypted_key_str = json.dumps(self._serialize_key(encryption_public_key))
        signature_key_str = json.dumps(self._serialize_key(signature_public_key))
        
        # Create a signature proving ownership of keys
        # In a real implementation, this would sign a specific message
        signature = bytes.fromhex("00" * 65)  # Placeholder signature
        
        # Estimate gas for the transaction
        gas_estimate = self.contract.functions.registerUser(
            user_id,
            encrypted_key_str,
            signature_key_str,
            signature
        ).estimate_gas({'from': account.address})
        
        # Prepare the transaction
        transaction = self.contract.functions.registerUser(
            user_id,
            encrypted_key_str,
            signature_key_str,
            signature
        ).build_transaction({
            'from': account.address,
            'gas': gas_estimate,
            'gasPrice': self.w3.eth.gas_price,
            'nonce': self.w3.eth.get_transaction_count(account.address),
        })
        
        # Sign the transaction
        signed_tx = self.w3.eth.account.sign_transaction(transaction, eth_private_key)
        
        # Send the transaction
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        
        # Wait for receipt
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        
        return receipt
    
    def record_authentication(self, eth_private_key, user_id, auth_signature):
        """
        Record a successful authentication on the blockchain
        
        Args:
            eth_private_key: Ethereum private key for transaction signing
            user_id: User identifier
            auth_signature: Signature from the authentication challenge
        """
        # Check if contract is initialized
        if self.contract is None:
            raise ValueError("Contract not initialized")
            
        # Create Ethereum account from private key
        account = Account.from_key(eth_private_key)
        
        # Estimate gas for the transaction
        gas_estimate = self.contract.functions.recordAuthentication(
            user_id,
            auth_signature
        ).estimate_gas({'from': account.address})
        
        # Prepare the transaction
        transaction = self.contract.functions.recordAuthentication(
            user_id,
            auth_signature
        ).build_transaction({
            'from': account.address,
            'gas': gas_estimate,
            'gasPrice': self.w3.eth.gas_price,
            'nonce': self.w3.eth.get_transaction_count(account.address),
        })
        
        # Sign the transaction
        signed_tx = self.w3.eth.account.sign_transaction(transaction, eth_private_key)
        
        # Send the transaction
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        
        # Wait for receipt
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        
        return receipt
    
    def rotate_keys(self, eth_private_key, user_id, new_encryption_key, new_signature_key, signature):
        """
        Rotate a user's keys on the blockchain
        
        Args:
            eth_private_key: Ethereum private key for transaction signing
            user_id: User identifier
            new_encryption_key: New encryption public key
            new_signature_key: New signature public key
            signature: Signature using the old keys to authorize rotation
        """
        # Check if contract is initialized
        if self.contract is None:
            raise ValueError("Contract not initialized")
            
        # Create Ethereum account from private key
        account = Account.from_key(eth_private_key)
        
        # Serialize the new public keys
        new_enc_key_str = json.dumps(self._serialize_key(new_encryption_key))
        new_sig_key_str = json.dumps(self._serialize_key(new_signature_key))
        
        # Estimate gas for the transaction
        gas_estimate = self.contract.functions.rotateKeys(
            user_id,
            new_enc_key_str,
            new_sig_key_str,
            signature
        ).estimate_gas({'from': account.address})
        
        # Prepare the transaction
        transaction = self.contract.functions.rotateKeys(
            user_id,
            new_enc_key_str,
            new_sig_key_str,
            signature
        ).build_transaction({
            'from': account.address,
            'gas': gas_estimate,
            'gasPrice': self.w3.eth.gas_price,
            'nonce': self.w3.eth.get_transaction_count(account.address),
        })
        
        # Sign the transaction
        signed_tx = self.w3.eth.account.sign_transaction(transaction, eth_private_key)
        
        # Send the transaction
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        
        # Wait for receipt
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        
        return receipt
    
    def revoke_keys(self, eth_private_key, user_id, reason="USER_REQUESTED"):
        """
        Revoke a user's keys on the blockchain
        
        Args:
            eth_private_key: Ethereum private key for transaction signing
            user_id: User identifier
            reason: Reason for key revocation
        """
        # Check if contract is initialized
        if self.contract is None:
            raise ValueError("Contract not initialized")
            
        # Create Ethereum account from private key
        account = Account.from_key(eth_private_key)
        
        # Estimate gas for the transaction
        gas_estimate = self.contract.functions.revokeKeys(
            user_id,
            reason
        ).estimate_gas({'from': account.address})
        
        # Prepare the transaction
        transaction = self.contract.functions.revokeKeys(
            user_id,
            reason
        ).build_transaction({
            'from': account.address,
            'gas': gas_estimate,
            'gasPrice': self.w3.eth.gas_price,
            'nonce': self.w3.eth.get_transaction_count(account.address),
        })
        
        # Sign the transaction
        signed_tx = self.w3.eth.account.sign_transaction(transaction, eth_private_key)
        
        # Send the transaction
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        
        # Wait for receipt
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        
        return receipt
    
    def get_user_keys(self, user_id):
        """
        Get a user's current public keys from the blockchain
        
        Args:
            user_id: User identifier
        """
        # Check if contract is initialized
        if self.contract is None:
            raise ValueError("Contract not initialized")
            
        # Call the view function
        keys = self.contract.functions.getUserKeys(user_id).call()
        
        # Parse the keys
        encryption_key = json.loads(keys[0])
        signature_key = json.loads(keys[1])
        is_active = keys[2]
        
        return {
            "encryption_key": encryption_key,
            "signature_key": signature_key,
            "is_active": is_active
        }
    
    def user_exists(self, user_id):
        """
        Check if a user exists on the blockchain
        
        Args:
            user_id: User identifier
        """
        # Check if contract is initialized
        if self.contract is None:
            raise ValueError("Contract not initialized")
            
        # Call the view function
        return self.contract.functions.userExists(user_id).call()
    
    def get_last_authentication(self, user_id):
        """
        Get a user's last authentication time
        
        Args:
            user_id: User identifier
        """
        # Check if contract is initialized
        if self.contract is None:
            raise ValueError("Contract not initialized")
            
        # Call the view function
        timestamp = self.contract.functions.getLastAuthentication(user_id).call()
        
        return timestamp
    
    def _serialize_key(self, key):
        """
        Serialize a key for blockchain storage
        """
        if isinstance(key, dict):
            return {k: v.hex() if isinstance(v, bytes) else v for k, v in key.items()}
        else:
            return key.hex() if isinstance(key, bytes) else str(key)