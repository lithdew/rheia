# rheia

A blockchain written in [Zig](https://ziglang.org).

## design

### concurrency
- thread-per-core architecture (thread pool for cpu-bound work)
- async disk and network i/o using io_uring (single-threaded event loop)
- (s/m)psc lock-free queues for cross-thread communication
- eventfd for cross-thread notifications

### consensus
- probabilistic finality of blocks and transactions
  - batching transactions into blocks increases transaction throughput
- sampling-based leaderless consensus
  - allows for voting-based consensus, proof-of-work-based consensus by providing custom sampling weight functions

### database
- sstables for on-disk storage format
- memtable for keeping track of blockchain state (robin hood hash table?)
- robin-hood hash tables for keeping track of pending transactions
- chain state represented as a sparse merkle trie of key-value pairs (akin to ethereum)
  - what's the most efficient way to maintain a sparse merkle trie over a sorted list of key-value pairs?
- upon finality of a block, flush all state changes and finalized transactions to sstable

### transaction gossip
- push/pull protocol (push out transactions, pull in transactions)
  - able to tune better latency vs. throughput per node
  - pull transactions more often than push, as push is a concern for dos attacks

### block sampling
- pull-based sampling protocol (pull in both finalized blocks and proposed blocks)

### smart contracts
- ebpf? webassembly?

## getting started

Run a node on port 9000:

```
$ zig run main.zig --name rheia -lc -O ReleaseFast
```

Run the benchmark tool to create, sign, and send transactions to 127.0.0.1:9000:

```
$ zig run bench.zig --name rheia_bench -lc -O ReleaseFast
```

## research

### lru cache

Rheia makes heavy use of LRU caches to keep track of unbounded sets of data that may be readily regenerated at any time in a lossy manner such as i.e. the set of all transactions that have already been gossiped to a particular destination address.

[Rheia's LRU cache](lru.zig) is an amalgamation of both a Robin Hood Hash Table and a Doubly-linked Deque. The idea of meshing a hash table and doubly-linked deque together to construct a LRU cache is inspired by [this blog post](https://medium.com/@udaysagar.2177/fastest-lru-cache-in-java-c22262de42ad).

An alternative LRU cache implementation was also experimented with, where deque entries and hash table entries were separately allocated. Such an implementation only yielded better overall throughput in comparison to Rheia's existing LRU cache implementation however when the cache's capacity is small and the maximum load factor is 50%. 

On my laptop, using Rheia's LRU cache with a max load factor of 50%, roughly:

1. 19.81 million entries can be upserted per second.
2. 20.19 million entries can be queried per second.
3. 9.97 million entries can be queried and removed per second.

The benchmark code is available [here](benchmarks/lru/main.zig). An example run is provided below.

```
$ zig run benchmarks/lru/main.zig -lc -O ReleaseFast --main-pkg-path .
info(linked-list lru w/ load factor 50% (4096 elements)): insert: 61.92us
info(linked-list lru w/ load factor 50% (4096 elements)): search: 64.429us
info(linked-list lru w/ load factor 50% (4096 elements)): delete: 100.595us
info(linked-list lru w/ load factor 50% (4096 elements)): put: 2010, get: 2010, del: 2010
info(intrusive lru w/ load factor 50% (4096 elements)): insert: 129.446us
info(intrusive lru w/ load factor 50% (4096 elements)): search: 79.754us
info(intrusive lru w/ load factor 50% (4096 elements)): delete: 169.099us
info(intrusive lru w/ load factor 50% (4096 elements)): put: 2010, get: 2010, del: 2010
info(linked-list lru w/ load factor 100% (4096 elements)): insert: 178.883us
info(linked-list lru w/ load factor 100% (4096 elements)): search: 37.786us
info(linked-list lru w/ load factor 100% (4096 elements)): delete: 37.522us
info(linked-list lru w/ load factor 100% (4096 elements)): put: 3798, get: 1905, del: 2827
info(intrusive lru w/ load factor 100% (4096 elements)): insert: 154.161us
info(intrusive lru w/ load factor 100% (4096 elements)): search: 21.533us
info(intrusive lru w/ load factor 100% (4096 elements)): delete: 61.936us
info(intrusive lru w/ load factor 100% (4096 elements)): put: 3798, get: 934, del: 2827
info(linked-list lru w/ load factor 50% (1 million elements)): insert: 79.469ms
info(linked-list lru w/ load factor 50% (1 million elements)): search: 48.164ms
info(linked-list lru w/ load factor 50% (1 million elements)): delete: 101.94ms
info(linked-list lru w/ load factor 50% (1 million elements)): put: 453964, get: 453964, del: 453964
info(intrusive lru w/ load factor 50% (1 million elements)): insert: 65.143ms
info(intrusive lru w/ load factor 50% (1 million elements)): search: 38.909ms
info(intrusive lru w/ load factor 50% (1 million elements)): delete: 95.001ms
info(intrusive lru w/ load factor 50% (1 million elements)): put: 453964, get: 453964, del: 453964
info(linked-list lru w/ load factor 100% (1 million elements)): insert: 123.995ms
info(linked-list lru w/ load factor 100% (1 million elements)): search: 29.77ms
info(linked-list lru w/ load factor 100% (1 million elements)): delete: 48.993ms
info(linked-list lru w/ load factor 100% (1 million elements)): put: 974504, get: 487369, del: 736132
info(intrusive lru w/ load factor 100% (1 million elements)): insert: 104.109ms
info(intrusive lru w/ load factor 100% (1 million elements)): search: 19.557ms
info(intrusive lru w/ load factor 100% (1 million elements)): delete: 47.728ms
info(intrusive lru w/ load factor 100% (1 million elements)): put: 974504, get: 249260, del: 736132
```

### mempool

One of the most critical data structures required by Rheia is a main-memory index that is meant to keep track of all transactions that have yet to be finalized under Rheia's consensus protocol (or in other words, a mempool).
    
A mempool in general maps transactions by their ID's to their contents. The ID of a transaction is the checksum of its contents. In Rheia's case, the checksum or ID of a transaction is computed using the BLAKE3 hash function with an output size of 256 bits.

There are two important things to look out for when it comes to figuring out the right data structure for Rheia's mempool given Rheia's choice of consensus protocol.

1. Iterating over all transactions by their ID lexicographically should be cheap.
2. Insertions/deletions should be fast assuming that there may be roughly 300k to 1 million transactions indexed at any moment in time.

A lot of different data structures were benchmarked, and the final data structure that I have decided to utilize as Rheia's mempool is a robin hood hash table.

To make the decision, the following data structures were benchmarked:

1. Robin Hood Hash Table ([lithdew/rheia](benchmarks/mempool/hash_map.zig))
1. B-Tree ([tidwall/btree.c](https://github.com/tidwall/btree.c))
2. Adaptive Radix Tree ([armon/libart](https://github.com/armon/libart))
3. Skiplist ([MauriceGit/skiplist](https://github.com/MauriceGit/skiplist) - ported to [zig](benchmarks/mempool/skiplist.zig))
4. Red-black Tree ([ziglang/std-lib-orphanage](https://github.com/ziglang/std-lib-orphanage/blob/master/std/rb.zig))
5. Radix Tree ([antirez/rax](https://github.com/antirez/rax) - ported to [zig](benchmarks/mempool/rax.zig))
6. Binary Heap ([ziglang/zig](https://github.com/ziglang/zig/blob/master/lib/std/priority_queue.zig))
7. Adaptive Radix Tree ([armon/libart](https://github.com/armon/libart) - ported to [zig](benchmarks/mempool/art.zig))
8. Adaptive Radix Tree ([travisstaloch/art.zig](https://github.com/travisstaloch/art.zig))

The robin hood hash table showed the highest average overall throughput over the following tests:

1. Insert 1 million different hashes into the data structure.
2. Check if 1 million different hashes exist in the data structure.
3. Delete 1 million different hashes from the data structure.

Using the robin hood hash table with a max load factor of 50%, roughly:

1. 19.58 million transactions can be indexed per second.
2. 25.07 million transactions can be searched for by their ID per second.
3. 20.91 million transactions can be searched for and unindexed by their ID per second.

The benchmark code is available [here](benchmarks/mempool/main.zig). An example run is provided below.

```
$ zig run benchmarks/mempool/main.zig benchmarks/mempool/*.c -I benchmarks/mempool -lc -fno-sanitize-c --name mempool --main-pkg-path . -O ReleaseFast

info(hash_map): insert: 45.657ms
info(hash_map): search: 33.438ms
info(hash_map): delete: 42.524ms
info(hash_map): put: 456520, get: 456520, del: 456520
info(btree): insert: 434.437ms
info(btree): search: 399.978ms
info(btree): delete: 423.974ms
info(red_black_tree): insert: 617.099ms
info(red_black_tree): search: 582.107ms
info(red_black_tree): skipping delete...
info(binary_heap): insert: 42.173ms
info(binary_heap): skipping search/delete...
info(skiplist): insert: 1.325s
info(skiplist): skipping search/delete...
info(libart): insert: 162.963ms
info(libart): search: 93.652ms
info(libart): delete: 253.205ms
info(art_travis): insert: 209.661ms
info(art_travis): search: 90.561ms
info(art_travis): delete: 217.101ms
info(art): insert: 165.919ms
info(art): search: 205.135ms
info(art): delete: 235.739ms
info(rax): insert: 566.947ms
info(rax): search: 380.085ms
info(rax): delete: 597.44ms
```