import os
import time
import multiprocessing
import numpy as np
from functools import wraps, partial

class CryptoOptimizer:
    """
    A utility for optimizing cryptographic operations
    """
    
    def __init__(self, crypto=None):
        """
        Initialize the optimizer
        
        Args:
            crypto: CoreCryptography instance
        """
        self.crypto = crypto
    
    def cached_key_derivation(self, key_derivation_func):
        """
        Decorator for caching key derivation results
        
        Args:
            key_derivation_func: Function to decorate
        """
        cache = {}
        
        @wraps(key_derivation_func)
        def wrapper(salt, passphrase, iterations=100000, *args, **kwargs):
            # Create a cache key
            cache_key = (salt, passphrase, iterations)
            
            # Check if result is already cached
            if cache_key in cache:
                return cache[cache_key]
                
            # Call the original function
            result = key_derivation_func(salt, passphrase, iterations, *args, **kwargs)
            
            # Cache the result
            cache[cache_key] = result
            
            return result
            
        return wrapper
    
    def parallelized_batch_operations(self, operation_func, items, num_processes=None):
        """
        Execute operations in parallel for a batch of items
        
        Args:
            operation_func: Function to execute
            items: List of items to process
            num_processes: Number of processes to use (defaults to CPU count)
        """
        if num_processes is None:
            num_processes = multiprocessing.cpu_count()
            
        # Create a pool of workers
        pool = multiprocessing.Pool(processes=num_processes)
        
        # Execute the operations in parallel
        results = pool.map(operation_func, items)
        
        # Close the pool
        pool.close()
        pool.join()
        
        return results
    
    def optimize_batch_key_generation(self, num_keys, user_id_prefix="user_", num_processes=None):
        """
        Optimize batch key generation
        
        Args:
            num_keys: Number of keys to generate
            user_id_prefix: Prefix for user IDs
            num_processes: Number of processes to use
        """
        if self.crypto is None:
            raise ValueError("CoreCryptography instance not provided")
            
        # Create user IDs
        user_ids = [f"{user_id_prefix}{i}" for i in range(num_keys)]
        
        # Define the key generation function
        def generate_key(user_id):
            return self.crypto.generate_user_keys(user_id)
            
        # Generate keys in parallel
        return self.parallelized_batch_operations(generate_key, user_ids, num_processes)
    
    def optimize_batch_encryption(self, public_key, messages, num_processes=None):
        """
        Optimize batch encryption
        
        Args:
            public_key: Public key to use for encryption
            messages: List of messages to encrypt
            num_processes: Number of processes to use
        """
        if self.crypto is None:
            raise ValueError("CoreCryptography instance not provided")
            
        # Define the encryption function
        def encrypt_message(message):
            return self.crypto.kem.encrypt_message(public_key, message)
            
        # Encrypt messages in parallel
        return self.parallelized_batch_operations(encrypt_message, messages, num_processes)
    
    def optimize_batch_decryption(self, private_key, encrypted_packages, num_processes=None):
        """
        Optimize batch decryption
        
        Args:
            private_key: Private key to use for decryption
            encrypted_packages: List of encrypted packages to decrypt
            num_processes: Number of processes to use
        """
        if self.crypto is None:
            raise ValueError("CoreCryptography instance not provided")
            
        # Define the decryption function
        def decrypt_package(package):
            return self.crypto.kem.decrypt_message(private_key, package)
            
        # Decrypt packages in parallel
        return self.parallelized_batch_operations(decrypt_package, encrypted_packages, num_processes)
    
    def optimize_batch_signing(self, private_key, messages, num_processes=None):
        """
        Optimize batch signing
        
        Args:
            private_key: Private key to use for signing
            messages: List of messages to sign
            num_processes: Number of processes to use
        """
        if self.crypto is None:
            raise ValueError("CoreCryptography instance not provided")
            
        # Define the signing function
        def sign_message(message):
            return self.crypto.signature.sign(private_key, message)
            
        # Sign messages in parallel
        return self.parallelized_batch_operations(sign_message, messages, num_processes)
    
    def optimize_batch_verification(self, public_key, messages_and_signatures, num_processes=None):
        """
        Optimize batch verification
        
        Args:
            public_key: Public key to use for verification
            messages_and_signatures: List of (message, signature) tuples
            num_processes: Number of processes to use
        """
        if self.crypto is None:
            raise ValueError("CoreCryptography instance not provided")
            
        # Define the verification function
        def verify_message_signature(message_and_signature):
            message, signature = message_and_signature
            return self.crypto.signature.verify(public_key, message, signature)
            
        # Verify signatures in parallel
        return self.parallelized_batch_operations(verify_message_signature, messages_and_signatures, num_processes)
    
    def optimize_key_operations(self):
        """
        Apply various optimizations to key operations
        """
        if self.crypto is None:
            raise ValueError("CoreCryptography instance not provided")
            
        # Add caching to key derivation
        if hasattr(self.crypto, 'key_derivation'):
            self.crypto.key_derivation = self.cached_key_derivation(self.crypto.key_derivation)
            
        print("Applied optimizations to key operations")
    
    def measure_optimization_impact(self, original_func, optimized_func, test_input, num_iterations=100):
        """
        Measure the impact of an optimization
        
        Args:
            original_func: Original function
            optimized_func: Optimized function
            test_input: Input to test with
            num_iterations: Number of iterations
        """
        # Measure original function
        original_times = []
        for _ in range(num_iterations):
            start_time = time.time()
            original_func(test_input)
            original_times.append(time.time() - start_time)
            
        # Measure optimized function
        optimized_times = []
        for _ in range(num_iterations):
            start_time = time.time()
            optimized_func(test_input)
            optimized_times.append(time.time() - start_time)
            
        # Calculate statistics
        original_mean = np.mean(original_times)
        optimized_mean = np.mean(optimized_times)
        speedup = original_mean / optimized_mean
        
        return {
            "original": {
                "mean": original_mean,
                "median": np.median(original_times),
                "std": np.std(original_times),
                "min": np.min(original_times),
                "max": np.max(original_times)
            },
            "optimized": {
                "mean": optimized_mean,
                "median": np.median(optimized_times),
                "std": np.std(optimized_times),
                "min": np.min(optimized_times),
                "max": np.max(optimized_times)
            },
            "speedup": speedup
        }
    
    def optimize_all(self):
        """
        Apply all optimizations
        """
        if self.crypto is None:
            raise ValueError("CoreCryptography instance not provided")
            
        # Apply key operation optimizations
        self.optimize_key_operations()
        
        print("All optimizations applied")