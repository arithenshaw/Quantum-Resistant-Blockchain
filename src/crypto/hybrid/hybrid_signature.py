import os
import json
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

#For this example we'll simulate dilithium for the pq signature

class SimulatedDilithium:
    @staticmethod
    def generate_keypair():
        """Generate a Dilithium key pair (simulated)."""
        private_key = os.urandom(32)
        public_key = os.urandom(1312) #Dilithium2 public key size
        return private_key, public_key
    
    @staticmethod
    def sign(private_key, message):
        """Sign a message with the private key (simulated)."""
        # In a real implementation, you would use the private key to sign the message.
        return os.urandom(2420) #Dilithium2 signature size
    
    @staticmethod
    def verify(public_key, message, signature):
        """Verify a signature with the public key (simulated)."""
        # In a real implementation, you would use the public key to verify the signature.
        return True  # Simulate successful verification
    
class HybridSignature:
    """
    Hybrid signature scheme combining traditional ECDSA with post-quantum Dilithium for quantum-resistance signatures.
    """

    def __init__(self):
        self.dilithium = SimulatedDilithium()

    def generate_keypair(self):
        """Generate a hybrid key pair (ECDSA + Dilithium)."""
        #Generate ECDSA key pair
        ecdsa_private_key = ec.generate_private_key(ec.SECP256R1())
        ecdsa_public_key = ecdsa_private_key.public_key()

        #Generate Dilithium key pair
        dilithium_private_key, dilithium_public_key = self.dilithium.generate_keypair()

        # Combine keys into a single hybrid key pair
        hybrid_private_key = {
            'ecdsa': ecdsa_private_key,
            'dilithium': dilithium_private_key
        }

        hybrid_public_key = {
            'ecdsa': ecdsa_public_key,
            'dilithium': dilithium_public_key
        }

        return hybrid_private_key, hybrid_public_key
    
    def serialize_public_key(self, public_key):
        """Serialize a hybrid public key for storage or transmission."""
        #serialize ECDSA public key
        ecdsa_bytes = public_key['ecdsa'].public_bytes(
            encoding=Encoding.DER,
            format=PublicFormat.SubjectPublicKeyInfo
        )

        #The Dilithium public key is already in bytes IN OUR SIMULATION
        dilithium_bytes = public_key['dilithium']

        #return both serialized keys as a dictionary
        return {
            'ecdsa': ecdsa_bytes.hex(),
            'dilithium': dilithium_bytes.hex()
        }
    
    def sign(self, private_key, message):
        """
        Sign a message using the hybrid signature scheme.
        """
        #Hash the message first
        if isinstance(message, str):
            message = message.encode('utf-8')
        message_hash = hashlib.sha256(message).digest()

        #ECDSA signature
        ecdsa_signature = private_key['ecdsa'].sign(
            message_hash,
            ec.ECDSA(hashes.SHA256())
        )

        #Dilithium signature
        dilithium_signature = self.dilithium.sign(
            private_key['dilithium'], 
            message_hash
        )

        #return both signatures as a dictionary
        return {
            'ecdsa': ecdsa_signature.hex(),
            'dilithium': dilithium_signature.hex()
        }
    
    def verify(self, public_key, message, signature):
        """
        Verify a hybrid signature
        Returns True only if both signatures verify successfully
        """

        #Hash the message first
        if isinstance(message, str):
            message = message.encode('utf-8')
        message_hash = hashlib.sha256(message).digest()
        
        #convert hex strings back to bytes
        if isinstance(signature['ecdsa'], str):
            ecdsa_sig_bytes = bytes.fromhex(signature['ecdsa'])
        else:
            ecdsa_sig_bytes = signature['ecdsa']

        if isinstance(signature['dilithium'], str):
            dilithium_sig_bytes = bytes.fromhex(signature['dilithium'])
        else:
            dilithium_sig_bytes = signature['dilithium']

        #verify ECDSA signature
        try:
            public_key['ecdsa'].verify(
                ecdsa_sig_bytes,
                message_hash,
                ec.ECDSA(hashes.SHA256())
            )
            ecdsa_valid = True
        except Exception:
            ecdsa_valid = False

        #verify Dilithium signature
        dilithium_valid = self.dilithium.verify(
            public_key['dilithium'],
            message_hash,
            dilithium_sig_bytes
        )

        #both must be valid for the hybrid signature to be valid
        return ecdsa_valid and dilithium_valid