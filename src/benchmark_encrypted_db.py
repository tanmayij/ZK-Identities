"""
benchmarking harness for encrypted database system.

measures latency and throughput for various:
- database sizes
- query selectivity
- attribute counts per user
- concurrent query loads
"""

import time
import json
import random
import secrets
import statistics
from typing import List, Dict, Any, Callable
from pathlib import Path

from encrypted_db_system import (
    EncryptedDatabaseServer,
    EncryptedDatabaseClient,
    EncryptedDatabaseVerifier,
    DeterministicCiphertext,
)
from zkid.blind_signatures import BlindSignatureIssuer


class BenchmarkConfig:
    """configuration for a benchmark run."""
    
    def __init__(self,
                 num_users: int,
                 attrs_per_user: int,
                 num_queries: int,
                 selectivity: float,
                 name: str = ""):
        self.num_users = num_users
        self.attrs_per_user = attrs_per_user
        self.num_queries = num_queries
        self.selectivity = selectivity
        self.name = name or f"users_{num_users}_attrs_{attrs_per_user}_queries_{num_queries}_sel_{selectivity}"


class BenchmarkResult:
    """results from a benchmark run."""
    
    def __init__(self, config: BenchmarkConfig):
        self.config = config
        self.query_latencies: List[float] = []
        self.predicate_times: List[float] = []
        self.inner_tree_times: List[float] = []
        self.outer_tree_times: List[float] = []
        self.signature_times: List[float] = []
        self.shuffle_times: List[float] = []
        self.matching_users_per_query: List[int] = []
        self.total_leaves_per_query: List[int] = []
    
    def add_query_result(self, metrics):
        self.query_latencies.append(metrics.total_time)
        self.predicate_times.append(metrics.predicate_eval_time)
        self.inner_tree_times.append(metrics.inner_tree_build_time)
        self.outer_tree_times.append(metrics.outer_tree_update_time)
        self.signature_times.append(metrics.signature_time)
        self.shuffle_times.append(metrics.shuffle_time)
        self.matching_users_per_query.append(metrics.num_matching_users)
        self.total_leaves_per_query.append(metrics.num_total_leaves)
    
    def get_summary(self) -> Dict[str, Any]:
        if not self.query_latencies:
            return {}
        
        def stats(data):
            return {
                'mean': statistics.mean(data),
                'median': statistics.median(data),
                'stdev': statistics.stdev(data) if len(data) > 1 else 0,
                'min': min(data),
                'max': max(data),
                'p95': statistics.quantiles(data, n=20)[18] if len(data) > 1 else data[0],
                'p99': statistics.quantiles(data, n=100)[98] if len(data) > 1 else data[0],
            }
        
        total_time = sum(self.query_latencies)
        throughput = len(self.query_latencies) / total_time if total_time > 0 else 0
        
        return {
            'config': {
                'name': self.config.name,
                'num_users': self.config.num_users,
                'attrs_per_user': self.config.attrs_per_user,
                'num_queries': self.config.num_queries,
                'selectivity': self.config.selectivity,
            },
            'performance': {
                'total_queries': len(self.query_latencies),
                'total_time_seconds': total_time,
                'throughput_qps': throughput,
                'latency_stats': stats(self.query_latencies),
            },
            'breakdown': {
                'predicate_eval': stats(self.predicate_times),
                'inner_tree_build': stats(self.inner_tree_times),
                'outer_tree_update': stats(self.outer_tree_times),
                'signature_gen': stats(self.signature_times),
                'shuffle': stats(self.shuffle_times),
            },
            'workload': {
                'avg_matching_users': statistics.mean(self.matching_users_per_query),
                'avg_total_leaves': statistics.mean(self.total_leaves_per_query),
            }
        }
    
    def print_summary(self):
        summary = self.get_summary()
        
        print(f"\n{'='*80}")
        print(f"benchmark: {summary['config']['name']}")
        print(f"{'='*80}")
        print(f"database: {summary['config']['num_users']} users x {summary['config']['attrs_per_user']} attrs")
        print(f"queries: {summary['performance']['total_queries']} @ {summary['config']['selectivity']*100:.1f}% selectivity")
        print(f"\nperformance:")
        print(f"  throughput: {summary['performance']['throughput_qps']:.2f} queries/sec")
        print(f"  latency (mean): {summary['performance']['latency_stats']['mean']*1000:.2f} ms")
        print(f"  latency (p95): {summary['performance']['latency_stats']['p95']*1000:.2f} ms")
        print(f"  latency (p99): {summary['performance']['latency_stats']['p99']*1000:.2f} ms")
        
        print(f"\nbreakdown (mean):")
        print(f"  predicate eval: {summary['breakdown']['predicate_eval']['mean']*1000:.2f} ms")
        print(f"  inner trees: {summary['breakdown']['inner_tree_build']['mean']*1000:.2f} ms")
        print(f"  outer tree: {summary['breakdown']['outer_tree_update']['mean']*1000:.2f} ms")
        print(f"  signatures: {summary['breakdown']['signature_gen']['mean']*1000:.2f} ms")
        print(f"  shuffle: {summary['breakdown']['shuffle']['mean']*1000:.2f} ms")
        
        print(f"\nworkload:")
        print(f"  avg matching users: {summary['workload']['avg_matching_users']:.1f}")
        print(f"  avg total leaves: {summary['workload']['avg_total_leaves']:.1f}")
        print(f"{'='*80}\n")


class DatabaseBenchmark:
    """benchmark runner for encrypted database system."""
    
    def __init__(self):
        self.results: List[BenchmarkResult] = []
    
    def generate_synthetic_users(self, num_users: int, attrs_per_user: int) -> tuple:
        """
        Generate synthetic user data for testing.
        
        Returns:
            (users_list, attribute_order)
        """
        # Generate attribute names
        attribute_order = [f"attr_{j}" for j in range(attrs_per_user)]
        
        users = []
        
        for i in range(num_users):
            uid = f"user_{i:06d}"
            pk_user = secrets.token_bytes(32)
            
            attributes = {}
            for attr_name in attribute_order:
                attr_value = f"value_{random.randint(0, 100)}"
                attributes[attr_name] = attr_value
            
            users.append({
                'uid': uid,
                'pk_user': pk_user,
                'attributes': attributes
            })
        
        return users, attribute_order
    
    def run_benchmark(self, config: BenchmarkConfig) -> BenchmarkResult:
        """run a single benchmark with given configuration."""
        
        print(f"\nrunning benchmark: {config.name}")
        print(f"  setting up database with {config.num_users} users...")
        
        encryption_key = secrets.token_bytes(32)
        issuer = BlindSignatureIssuer(key_size=2048)
        
        # Generate users and attribute schema
        users, attribute_order = self.generate_synthetic_users(config.num_users, config.attrs_per_user)
        
        # Initialize server with attribute order
        server = EncryptedDatabaseServer(
            encryption_key, 
            issuer,
            attribute_order=attribute_order
        )
        
        for user in users:
            server.load_user(user['uid'], user['pk_user'], user['attributes'])
        
        print(f"  executing {config.num_queries} queries...")
        
        result = BenchmarkResult(config)
        
        for q in range(config.num_queries):
            threshold = random.randint(0, 100)
            
            def predicate(uid, encrypted_attrs):
                return random.random() < config.selectivity
            
            response = server.query(predicate, query_id=f"bench_q_{q}")
            result.add_query_result(response.metrics)
            
            if (q + 1) % max(1, config.num_queries // 10) == 0:
                print(f"    progress: {q+1}/{config.num_queries} queries")
        
        self.results.append(result)
        return result
    
    def run_suite(self):
        """run a comprehensive benchmark suite."""
        
        print("\n" + "="*80)
        print("encrypted database benchmark suite")
        print("="*80)
        
        configs = [
            BenchmarkConfig(num_users=100, attrs_per_user=5, num_queries=50, selectivity=0.1,
                          name="small_db_low_selectivity"),
            BenchmarkConfig(num_users=100, attrs_per_user=5, num_queries=50, selectivity=0.5,
                          name="small_db_medium_selectivity"),
            BenchmarkConfig(num_users=500, attrs_per_user=10, num_queries=100, selectivity=0.2,
                          name="medium_db_low_selectivity"),
            BenchmarkConfig(num_users=1000, attrs_per_user=10, num_queries=100, selectivity=0.1,
                          name="large_db_low_selectivity"),
            BenchmarkConfig(num_users=1000, attrs_per_user=20, num_queries=50, selectivity=0.05,
                          name="large_db_many_attrs"),
        ]
        
        for config in configs:
            result = self.run_benchmark(config)
            result.print_summary()
        
        return self.results
    
    def save_results(self, output_path: Path):
        """save all benchmark results to json file."""
        data = {
            'timestamp': time.time(),
            'results': [r.get_summary() for r in self.results]
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\nbenchmark results saved to: {output_path}")


def run_quick_benchmark():
    """run a quick benchmark for testing."""
    benchmark = DatabaseBenchmark()
    
    config = BenchmarkConfig(
        num_users=50,
        attrs_per_user=5,
        num_queries=20,
        selectivity=0.3,
        name="quick_test"
    )
    
    result = benchmark.run_benchmark(config)
    result.print_summary()
    
    return result


def run_full_suite():
    """run the full benchmark suite."""
    benchmark = DatabaseBenchmark()
    results = benchmark.run_suite()
    
    output_dir = Path("benchmarks")
    output_dir.mkdir(exist_ok=True)
    
    benchmark.save_results(output_dir / f"results_{int(time.time())}.json")
    
    return results


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--full":
        run_full_suite()
    else:
        run_quick_benchmark()
