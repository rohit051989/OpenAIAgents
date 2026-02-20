# VDI Disk Speed Test
# Run this to confirm disk I/O is the bottleneck

import time
import os

print("=" * 80)
print("VDI Disk Performance Test")
print("=" * 80)

# Test 1: Sequential write performance
print("\n1. Testing sequential write speed...")
test_file = "D:\\test_disk_speed.tmp"

start = time.time()
with open(test_file, 'wb') as f:
    for i in range(10000):
        f.write(b'x' * 1024)  # Write 1KB blocks, 10000 times = 10MB
elapsed = time.time() - start

mb_written = 10
throughput = mb_written / elapsed

print(f"   Wrote 10MB in {elapsed:.2f} seconds")
print(f"   Throughput: {throughput:.2f} MB/s")

if throughput < 5:
    print("   ⚠️  VERY SLOW - VDI disk is severe bottleneck!")
    print("   Typical network storage: 5-20 MB/s")
    print("   Typical local SSD: 200-500 MB/s")
elif throughput < 50:
    print("   ⚠️  SLOW - Network attached storage")
    print("   This explains your 29 stmt/s performance")
else:
    print("   ✅ Good disk performance")

# Test 2: Sync write performance (simulates Neo4j transaction commits)
print("\n2. Testing sync write speed (simulates database commits)...")

start = time.time()
with open(test_file, 'wb') as f:
    for i in range(100):
        f.write(b'x' * 1024)
        f.flush()
        os.fsync(f.fileno())  # Force OS to write to disk (like Neo4j commit)
elapsed = time.time() - start

syncs_per_sec = 100 / elapsed

print(f"   100 synced writes in {elapsed:.2f} seconds")
print(f"   Sync rate: {syncs_per_sec:.1f} syncs/second")

if syncs_per_sec < 50:
    print("   ⚠️  CRITICAL - This is why Neo4j is slow!")
    print(f"   Your Neo4j can only commit ~{syncs_per_sec:.0f} transactions/second")
    print("   This matches your 29 stmt/s observation")
    print("\n   SOLUTION: Use UNWIND batching (reduces commits by 1000x)")
elif syncs_per_sec < 200:
    print("   ⚠️  Disk sync is slow")
    print("   Recommendation: Use UNWIND batching")
else:
    print("   ✅ Good sync performance")

# Cleanup
os.remove(test_file)

print("\n" + "=" * 80)
print("CONCLUSION:")
if syncs_per_sec < 50:
    print("Your VDI disk is TOO SLOW for individual statement execution.")
    print("NO amount of Neo4j memory will fix this.")
    print("")
    print("REQUIRED: Switch to UNWIND batching (refactor code)")
    print("Expected improvement: 14 hours → 30-60 minutes")
else:
    print("Disk performance is acceptable.")
    print("Performance issue may be elsewhere (check Neo4j logs)")
print("=" * 80)
