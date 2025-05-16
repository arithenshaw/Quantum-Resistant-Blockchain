import os
import time
import json
import hashlib
import base64
from src.crypto.core_crypto import CoreCryptography

class ChallengeResponseAuth:
    """
    Implementation of a quantum-resistant challenge-response authentication mechanism
    """
    
    def __init__(self, crypto=None):
        self.crypto = crypto or CoreCryptography()
        self.challenges = {}  # In production, use a proper database
    
    def create_challenge(self, user_id, user_public_key):
        """
        Create a challenge for the user to sign
        """
        # Generate a random nonce
        nonce = os.urandom(32)
        nonce_hex = nonce.hex()
        
        # Current timestamp
        timestamp = int(time.time())
        
        # Create a challenge ID
        challenge_id = hashlib.sha256(f"{user_id}:{nonce_hex}:{timestamp}".encode()).hexdigest()
        
        # Create challenge data combining multiple elements for increased security
        challenge_data = {
            "type": "AUTH_CHALLENGE",
            "user_id": user_id,
            "nonce": nonce_hex,
            "timestamp": timestamp,
            "expires_at": timestamp + 300  # 5 minutes expiration
        }
        
        # Serialize the challenge data
        challenge_json = json.dumps(challenge_data, sort_keys=True)
        challenge_bytes = challenge_json.encode('utf-8')
        
        # Encrypt the challenge with the user's public key
        encrypted_challenge = self.crypto.kem.encrypt_message(
            user_public_key['encryption']['public'],  
            challenge_bytes
        )
        
        # Store the challenge for verification
        self.challenges[challenge_id] = {
            "data": challenge_data,
            "plain_challenge": challenge_bytes,
            "used": False
        }
        
        # Return the challenge to send to the user
        return {
            "challenge_id": challenge_id,
            "encrypted_challenge": encrypted_challenge
        }
    
    def verify_response(self, challenge_id, response):
        """
        Verify a challenge response from the user
        """
        # Check if challenge exists
        if challenge_id not in self.challenges:
            return False, "Challenge not found"
        
        challenge = self.challenges[challenge_id]
        
        # Check if challenge is expired
        if challenge["data"]["expires_at"] < int(time.time()):
            return False, "Challenge expired"
        
        # Check if challenge was already used
        if challenge["used"]:
            return False, "Challenge already used"
        
        # Mark challenge as used to prevent replay attacks
        challenge["used"] = True
        
        # Extract signature from response
        signature = response.get("signature")
        if not signature:
            return False, "Missing signature"
        
        # Extract user's public key from response or fetch from your system
        user_public_key = response.get("public_key") 
        # In a real system, you'd fetch this from your database based on user_id
        
        # Verify the signature
        try:
            is_valid = self.crypto.signature.verify(
                user_public_key['signature']['public'],
                challenge["plain_challenge"],
                signature
            )
            
            if is_valid:
                return True, "Authentication successful"
            else:
                return False, "Invalid signature"
        except Exception as e:
            return False, f"Verification error: {str(e)}"
    
    def create_response(self, challenge_package, user_private_key):
        """
        Create a response to a challenge (client-side)
        """
        # Extract challenge
        challenge_id = challenge_package["challenge_id"]
        encrypted_challenge = challenge_package["encrypted_challenge"]
        
        # Decrypt the challenge using the user's private key
        try:
            decrypted_challenge = self.crypto.kem.decrypt_message(
                user_private_key['encryption'],
                encrypted_challenge
            )
            
            # Parse the challenge JSON
            challenge_data = json.loads(decrypted_challenge.decode('utf-8'))
            
            # Sign the challenge
            signature = self.crypto.signature.sign(
                user_private_key['signature'],
                decrypted_challenge
            )
            
            # Create response
            response = {
                "challenge_id": challenge_id,
                "user_id": challenge_data["user_id"],
                "nonce": challenge_data["nonce"],
                "timestamp": int(time.time()),
                "signature": signature
            }
            
            return response
            
        except Exception as e:
            return {"error": f"Failed to create response: {str(e)}"}
    
    def clean_expired_challenges(self):
        """
        Remove expired challenges from memory
        """
        current_time = int(time.time())
        expired_ids = []
        
        for challenge_id, challenge in self.challenges.items():
            if challenge["data"]["expires_at"] < current_time:
                expired_ids.append(challenge_id)
        
        for challenge_id in expired_ids:
            del self.challenges[challenge_id]
        
        return len(expired_ids)

# Example usage
def challenge_response_flow_example():
    """
    Example showing the full challenge-response flow
    """
    # Initialize the components
    crypto = CoreCryptography()
    cr_auth = ChallengeResponseAuth(crypto)
    
    # Generate user keys (this would typically happen during registration)
    user_keys = crypto.generate_user_keys(user_id="alice123")
    user_private_key = user_keys
    user_public_key = {
        'encryption': {'public': user_keys['encryption']['public']},
        'signature': {'public': user_keys['signature']['public']}
    }
    
    # === SERVER SIDE ===
    # Create a challenge
    challenge = cr_auth.create_challenge("alice123", user_public_key)
    
    # In a real application, this challenge would be sent to the client
    
    # === CLIENT SIDE ===
    # Client receives the challenge and creates a response
    response = cr_auth.create_response(challenge, user_private_key)
    
    # In a real application, this response would be sent back to the server
    
    # === SERVER SIDE AGAIN ===
    # Server verifies the response
    is_valid, message = cr_auth.verify_response(challenge["challenge_id"], response)
    
    return is_valid, message