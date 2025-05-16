import time
import cProfile
import pstats
import io
import os
import json
import multiprocessing
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np

from src.crypto.core_crypto import CoreCryptography
from src.crypto.hybrid.hybrid_kem import HybridKEM
from src.crypto.hybrid.hybrid_signature import HybridSignature
from src.auth.protocol.auth_protocol import AuthenticationProtocol
from src.auth.protocol.challenge_response import ChallengeResponseAuth
from src.blockchain.transaction import TransactionFormat

class PerformanceProfiler:
    """
    A utility for profiling and optimizing the quantum-resistant blockchain authentication system
    """
    
    def __init__(self, output_dir=None):
        """
        Initialize the profiler
        
        Args:
            output_dir: Directory to store profiling results
        """
        self.output_dir = output_dir or Path("./profiling_results")
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialize components
        self.crypto = CoreCryptography()
        self.kem = HybridKEM()
        self.signature = HybridSignature()
        self.auth_protocol = AuthenticationProtocol(crypto=self.crypto)
        self.challenge_response = ChallengeResponseAuth(crypto=self.crypto)
        
        # Storage for benchmark results
        self.results = {}
    
    def profile_function(self, func, *args, **kwargs):
        """
        Profile a function using cProfile
        
        Args:
            func: Function to profile
            args: Arguments to pass to the function
            kwargs: Keyword arguments to pass to the function
        """
        # Create a profiler
        profiler = cProfile.Profile()
        
        # Start profiling
        profiler.enable()
        
        # Run the function
        result = func(*args, **kwargs)
        
        # End profiling
        profiler.disable()
        
        # Get stats
        s = io.StringIO()
        ps = pstats.Stats(profiler, stream=s).sort_stats('cumulative')
        ps.print_stats()
        
        return result, s.getvalue()
    
    def benchmark_key_generation(self, num_iterations=100):
        """
        Benchmark key generation performance
        
        Args:
            num_iterations: Number of iterations for the benchmark
        """
        print(f"Benchmarking key generation ({num_iterations} iterations)...")
        
        # Measure ECC key generation
        ecc_times = []
        for _ in range(num_iterations):
            start_time = time.time()
            # This is just a placeholder for actual ECC key generation
            self.kem.generate_keypair()
            ecc_times.append(time.time() - start_time)
        
        # Measure hybrid key generation
        hybrid_times = []
        for _ in range(num_iterations):
            start_time = time.time()
            self.crypto.generate_user_keys()
            hybrid_times.append(time.time() - start_time)
        
        # Store results
        self.results["key_generation"] = {
            "ecc": {
                "mean": np.mean(ecc_times),
                "median": np.median(ecc_times),
                "std": np.std(ecc_times),
                "min": np.min(ecc_times),
                "max": np.max(ecc_times)
            },
            "hybrid": {
                "mean": np.mean(hybrid_times),
                "median": np.median(hybrid_times),
                "std": np.std(hybrid_times),
                "min": np.min(hybrid_times),
                "max": np.max(hybrid_times)
            }
        }
        
        print(f"ECC key generation: {np.mean(ecc_times):.6f}s (mean)")
        print(f"Hybrid key generation: {np.mean(hybrid_times):.6f}s (mean)")
        
        # Plot results
        self._plot_comparison("Key Generation Times", "Time (s)", 
                             ["ECC", "Hybrid"], 
                             [ecc_times, hybrid_times],
                             "key_generation_times.png")
    
    def benchmark_encryption(self, message_sizes=[128, 512, 1024, 4096, 16384], num_iterations=50):
        """
        Benchmark encryption performance
        
        Args:
            message_sizes: List of message sizes to test (in bytes)
            num_iterations: Number of iterations for each message size
        """
        print(f"Benchmarking encryption ({len(message_sizes)} sizes, {num_iterations} iterations each)...")
        
        # Generate a key pair for testing
        private_key, public_key = self.kem.generate_keypair()
        
        results = {}
        for size in message_sizes:
            print(f"Testing message size: {size} bytes")
            
            # Create a test message
            test_message = os.urandom(size)
            
            # Measure encryption times
            encryption_times = []
            for _ in range(num_iterations):
                start_time = time.time()
                encryption_package = self.kem.encrypt_message(public_key, test_message)
                encryption_times.append(time.time() - start_time)
            
            # Measure decryption times
            decryption_times = []
            for _ in range(num_iterations):
                # Create a new encryption package each time to avoid caching effects
                encryption_package = self.kem.encrypt_message(public_key, test_message)
                
                start_time = time.time()
                self.kem.decrypt_message(private_key, encryption_package)
                decryption_times.append(time.time() - start_time)
            
            # Store results
            results[size] = {
                "encryption": {
                    "mean": np.mean(encryption_times),
                    "median": np.median(encryption_times),
                    "std": np.std(encryption_times),
                    "min": np.min(encryption_times),
                    "max": np.max(encryption_times)
                },
                "decryption": {
                    "mean": np.mean(decryption_times),
                    "median": np.median(decryption_times),
                    "std": np.std(decryption_times),
                    "min": np.min(decryption_times),
                    "max": np.max(decryption_times)
                }
            }
            
            print(f"Encryption: {np.mean(encryption_times):.6f}s (mean)")
            print(f"Decryption: {np.mean(decryption_times):.6f}s (mean)")
        
        # Store results
        self.results["encryption"] = results
        
        # Plot results
        self._plot_scaling("Message Size vs. Encryption Time", 
                         "Message Size (bytes)", "Time (s)",
                         message_sizes, 
                         [results[size]["encryption"]["mean"] for size in message_sizes],
                         "encryption_scaling.png")
        
        self._plot_scaling("Message Size vs. Decryption Time", 
                         "Message Size (bytes)", "Time (s)",
                         message_sizes, 
                         [results[size]["decryption"]["mean"] for size in message_sizes],
                         "decryption_scaling.png")
    
    def benchmark_signatures(self, message_sizes=[128, 512, 1024, 4096, 16384], num_iterations=50):
        """
        Benchmark signature performance
        
        Args:
            message_sizes: List of message sizes to test (in bytes)
            num_iterations: Number of iterations for each message size
        """
        print(f"Benchmarking signatures ({len(message_sizes)} sizes, {num_iterations} iterations each)...")
        
        # Generate a key pair for testing
        private_key, public_key = self.signature.generate_keypair()
        
        results = {}
        for size in message_sizes:
            print(f"Testing message size: {size} bytes")
            
            # Create a test message
            test_message = os.urandom(size)
            
            # Measure signing times
            signing_times = []
            for _ in range(num_iterations):
                start_time = time.time()
                signature = self.signature.sign(private_key, test_message)
                signing_times.append(time.time() - start_time)
            
            # Measure verification times
            verification_times = []
            for _ in range(num_iterations):
                # Use the same signature for each verification
                signature = self.signature.sign(private_key, test_message)
                
                start_time = time.time()
                self.signature.verify(public_key, test_message, signature)
                verification_times.append(time.time() - start_time)
            
            # Store results
            results[size] = {
                "signing": {
                    "mean": np.mean(signing_times),
                    "median": np.median(signing_times),
                    "std": np.std(signing_times),
                    "min": np.min(signing_times),
                    "max": np.max(signing_times)
                },
                "verification": {
                    "mean": np.mean(verification_times),
                    "median": np.median(verification_times),
                    "std": np.std(verification_times),
                    "min": np.min(verification_times),
                    "max": np.max(verification_times)
                }
            }
            
            print(f"Signing: {np.mean(signing_times):.6f}s (mean)")
            print(f"Verification: {np.mean(verification_times):.6f}s (mean)")
        
        # Store results
        self.results["signatures"] = results
        
        # Plot results
        self._plot_scaling("Message Size vs. Signing Time", 
                         "Message Size (bytes)", "Time (s)",
                         message_sizes, 
                         [results[size]["signing"]["mean"] for size in message_sizes],
                         "signing_scaling.png")
        
        self._plot_scaling("Message Size vs. Verification Time", 
                         "Message Size (bytes)", "Time (s)",
                         message_sizes, 
                         [results[size]["verification"]["mean"] for size in message_sizes],
                         "verification_scaling.png")
    
    def benchmark_authentication_flow(self, num_iterations=50):
        """
        Benchmark the full authentication flow
        
        Args:
            num_iterations: Number of iterations for the benchmark
        """
        print(f"Benchmarking authentication flow ({num_iterations} iterations)...")
        
        # Times for each stage
        registration_times = []
        challenge_generation_times = []
        response_generation_times = []
        verification_times = []
        
        for i in range(num_iterations):
            print(f"Iteration {i+1}/{num_iterations}")
            
            # User registration
            user_id = f"test_user_{os.urandom(4).hex()}"
            
            start_time = time.time()
            key_bundle, transaction = self.auth_protocol.register_user(user_id)
            registration_times.append(time.time() - start_time)
            
            # Public key bundle
            public_key_bundle = {
                'encryption': {'public': key_bundle['encryption']['public']},
                'signature': {'public': key_bundle['signature']['public']}
            }
            
            # Challenge generation
            start_time = time.time()
            challenge = self.auth_protocol.generate_challenge(user_id, public_key_bundle)
            challenge_generation_times.append(time.time() - start_time)
            
            # Response generation
            start_time = time.time()
            response = self.auth_protocol.authenticate_user(user_id, key_bundle, challenge)
            response_generation_times.append(time.time() - start_time)
            
            # Verification
            start_time = time.time()
            is_valid, transaction = self.auth_protocol.verify_challenge_response(
                challenge["challenge_id"],
                response,
                public_key_bundle
            )
            verification_times.append(time.time() - start_time)
        
        # Store results
        self.results["authentication_flow"] = {
            "registration": {
                "mean": np.mean(registration_times),
                "median": np.median(registration_times),
                "std": np.std(registration_times),
                "min": np.min(registration_times),
                "max": np.max(registration_times)
            },
            "challenge_generation": {
                "mean": np.mean(challenge_generation_times),
                "median": np.median(challenge_generation_times),
                "std": np.std(challenge_generation_times),
                "min": np.min(challenge_generation_times),
                "max": np.max(challenge_generation_times)
            },
            "response_generation": {
                "mean": np.mean(response_generation_times),
                "median": np.median(response_generation_times),
                "std": np.std(response_generation_times),
                "min": np.min(response_generation_times),
                "max": np.max(response_generation_times)
            },
            "verification": {
                "mean": np.mean(verification_times),
                "median": np.median(verification_times),
                "std": np.std(verification_times),
                "min": np.min(verification_times),
                "max": np.max(verification_times)
            }
        }
        
        print(f"Registration: {np.mean(registration_times):.6f}s (mean)")
        print(f"Challenge generation: {np.mean(challenge_generation_times):.6f}s (mean)")
        print(f"Response generation: {np.mean(response_generation_times):.6f}s (mean)")
        print(f"Verification: {np.mean(verification_times):.6f}s (mean)")
        
        # Plot results
        self._plot_comparison("Authentication Flow Times", "Time (s)", 
                             ["Registration", "Challenge\nGeneration", "Response\nGeneration", "Verification"], 
                             [registration_times, challenge_generation_times, response_generation_times, verification_times],
                             "authentication_flow_times.png")
    
    def benchmark_parallel_operations(self, num_users=100, num_processes=None):
        """
        Benchmark parallel operations
        
        Args:
            num_users: Number of users to simulate
            num_processes: Number of processes to use (defaults to CPU count)
        """
        print(f"Benchmarking parallel operations ({num_users} users)...")
        
        if num_processes is None:
            num_processes = multiprocessing.cpu_count()
            
        print(f"Using {num_processes} processes")
        
        # Create a pool of workers
        pool = multiprocessing.Pool(processes=num_processes)
        
        # Simulate user registration
        start_time = time.time()
        user_data = [(f"user_{i}", f"passphrase_{i}") for i in range(num_users)]
        results = pool.starmap(self._register_user_wrapper, user_data)
        registration_time = time.time() - start_time
        
        print(f"Parallel registration of {num_users} users: {registration_time:.6f}s")
        print(f"Average time per user: {registration_time/num_users:.6f}s")
        
        # Store results
        self.results["parallel_operations"] = {
            "num_users": num_users,
            "num_processes": num_processes,
            "total_registration_time": registration_time,
            "average_registration_time": registration_time / num_users
        }
        
        # Plot scaling with number of processes
        self._benchmark_process_scaling(num_users=100)
    
    def _benchmark_process_scaling(self, num_users=100, max_processes=None):
        """
        Benchmark scaling with number of processes
        
        Args:
            num_users: Number of users to simulate
            max_processes: Maximum number of processes to test
        """
        if max_processes is None:
            max_processes = multiprocessing.cpu_count()
            
        print(f"Benchmarking process scaling (1-{max_processes} processes, {num_users} users)...")
        
        process_counts = list(range(1, max_processes + 1))
        times = []
        
        for num_processes in process_counts:
            print(f"Testing with {num_processes} processes...")
            
            # Create a pool of workers
            pool = multiprocessing.Pool(processes=num_processes)
            
            # Simulate user registration
            start_time = time.time()
            user_data = [(f"user_{i}", f"passphrase_{i}") for i in range(num_users)]
            results = pool.starmap(self._register_user_wrapper, user_data)
            registration_time = time.time() - start_time
            
            times.append(registration_time)
            
            print(f"Registration time: {registration_time:.6f}s")
            
        # Store results
        self.results["process_scaling"] = {
            "num_users": num_users,
            "process_counts": process_counts,
            "times": times
        }
        
        # Plot results
        self._plot_scaling("Process Scaling", 
                         "Number of Processes", "Time (s)",
                         process_counts, 
                         times,
                         "process_scaling.png")
    
    def _register_user_wrapper(self, user_id, passphrase):
        """
        Wrapper for user registration (used in parallel benchmarks)
        
        Args:
            user_id: User identifier
            passphrase: User passphrase
        """
        return self.auth_protocol.register_user(user_id, passphrase)
    
    def _plot_comparison(self, title, ylabel, labels, data_sets, filename):
        """
        Create a box plot comparing multiple data sets
        
        Args:
            title: Plot title
            ylabel: Y-axis label
            labels: Labels for each data set
            data_sets: List of data sets to plot
            filename: Output filename
        """
        plt.figure(figsize=(10, 6))
        plt.boxplot(data_sets)
        plt.title(title)
        plt.ylabel(ylabel)
        plt.xticks(range(1, len(labels) + 1), labels)
        plt.grid(True, linestyle='--', alpha=0.7)
        
        # Save the plot
        plt.savefig(self.output_dir / filename, dpi=300, bbox_inches='tight')
        plt.close()
    
    def _plot_scaling(self, title, xlabel, ylabel, x_values, y_values, filename):
        """
        Create a line plot showing scaling
        
        Args:
            title: Plot title
            xlabel: X-axis label
            ylabel: Y-axis label
            x_values: X-axis values
            y_values: Y-axis values
            filename: Output filename
        """
        plt.figure(figsize=(10, 6))
        plt.plot(x_values, y_values, 'o-', linewidth=2)
        plt.title(title)
        plt.xlabel(xlabel)
        plt.ylabel(ylabel)
        plt.grid(True, linestyle='--', alpha=0.7)
        
        # Use log scales if appropriate
        if max(x_values) / min(x_values) > 100:
            plt.xscale('log')
        if max(y_values) / min(y_values) > 100:
            plt.yscale('log')
            
        # Save the plot
        plt.savefig(self.output_dir / filename, dpi=300, bbox_inches='tight')
        plt.close()
    
    def save_results(self, filename="profiling_results.json"):
        """
        Save benchmark results to a file
        
        Args:
            filename: Output filename
        """
        # Convert numpy values to Python types
        def convert_numpy(obj):
            if isinstance(obj, dict):
                return {k: convert_numpy(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_numpy(item) for item in obj]
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, (np.int_, np.intc, np.intp, np.int8, np.int16, np.int32, np.int64, 
                                np.uint8, np.uint16, np.uint32, np.uint64)):
                return int(obj)
            elif isinstance(obj, (np.float_, np.float16, np.float32, np.float64)):
                return float(obj)
            elif isinstance(obj, (np.bool_)):
                return bool(obj)
            else:
                return obj
        
        # Convert results
        converted_results = convert_numpy(self.results)
        
        # Save to file
        with open(self.output_dir / filename, 'w') as f:
            json.dump(converted_results, f, indent=2)
            
        print(f"Results saved to {self.output_dir / filename}")
    
    def run_all_benchmarks(self):
        """
        Run all benchmarks
        """
        print("Running all benchmarks...")
        
        # Run individual benchmarks
        self.benchmark_key_generation()
        self.benchmark_encryption()
        self.benchmark_signatures()
        self.benchmark_authentication_flow()
        self.benchmark_parallel_operations()
        
        # Save results
        self.save_results()
        
        print("All benchmarks completed.")