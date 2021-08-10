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
- memtable for keeping track of pending transactions (skiplist? rb-tree? b-tree? rax? trie?)
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

```
$ zig run main.zig --name rheia -lc
```

## research

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

Using the robin hood hash table, roughly:

1. 19.58 million transactions can be indexed per second.
2. 25.07 million transactions can be searched for by their ID per second.
3. 20.91 million transactions can be searched for and unindexed by their ID per second.

The benchmark code is available [here](benchmarks/mempool/main.zig). An example run is provided below.

```
$ zig run benchmarks/mempool/main.zig benchmarks/mempool/*.c -I benchmarks/mempool -lc -fno-sanitize-c --name mempool -O ReleaseFast

info(hash_map): insert: 51.063ms
info(hash_map): search: 39.878ms
info(hash_map): delete: 47.812ms
info(hash_map): put: 456520, get: 456520, del: 456520
info(btree): insert: 449.879ms
info(btree): search: 426.655ms
info(btree): delete: 456.117ms
info(red_black_tree): insert: 655.393ms
info(red_black_tree): search: 629.375ms
info(red_black_tree): skipping delete...
info(binary_heap): insert: 42.693ms
info(binary_heap): skipping search/delete...
info(skiplist): insert: 1.476s
info(skiplist): skipping search/delete...
info(libart): insert: 133.669ms
info(libart): search: 79.571ms
info(libart): delete: 221.038ms
info(art_travis): insert: 191.35ms
info(art_travis): search: 79.108ms
info(art_travis): delete: 203.434ms
info(art): insert: 174.168ms
info(art): search: 164.825ms
info(art): delete: 186.713ms
info(rax): insert: 449.149ms
info(rax): search: 312.79ms
info(rax): delete: 555.432ms
```