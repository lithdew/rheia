# rheia

A blockchain written in [Zig](https://ziglang.org).

## design

### concurrency
- thread-per-core architecture (thread pools for cpu-bound work, and i/o bound work)
- async disk and network i/o using io_uring (multi-threaded event loop)
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

1. Iterating over all transactions by their ID lexicographically should
   be cheap.
2. Insertions/deletions should be fast assuming that there may be
   roughly 300k to 1 million transactions indexed at any moment in time.

A lot of different data structures were benchmarked, and the final data structure that I have decided to utilize as Rheia's mempool is the adaptive radix tree.

To make the decision, the following data structures were benchmarked:

1. B-Tree ([tidwall/btree.c](https://github.com/tidwall/btree.c))
2. Adaptive Radix Tree ([armon/libart](https://github.com/armon/libart))
3. Skiplist ([MauriceGit/skiplist](https://github.com/MauriceGit/skiplist) - ported to [zig](benchmarks/mempool/skiplist.zig))
4. Red-black tree ([ziglang/std-lib-orphanage](https://github.com/ziglang/std-lib-orphanage/blob/master/std/rb.zig))
5. Radix Tree ([antirez/rax](https://github.com/antirez/rax) - ported to [zig](benchmarks/mempool/rax.zig))
6. Binary Heap ([ziglang/zig](https://github.com/ziglang/zig/blob/master/lib/std/priority_queue.zig))
7. Adaptive Radix Tree ([armon/libart](https://github.com/armon/libart) - ported to [zig](benchmarks/mempool/art.zig))
8. Adaptive Radix Tree ([travisstaloch/art.zig](https://github.com/travisstaloch/art.zig))

The adaptive radix tree showed the highest average overall throughput over the following tests:

1. Insert 1 million different hashes into the data structure.
2. Check if 1 million different hashes exist in the data structure.
3. Delete 1 million different hashes from the data structure.

Roughly 2 to 3 million hashes can be inserted per second from the benchmarks I wrote, which roughly translates into Rheia being able to index roughly 2 to 3 million transactions per second on my laptop.

The benchmark code is available [here](benchmarks/mempool/main.zig). An example run is provided below.

```
$ zig run benchmarks/mempool/main.zig benchmarks/mempool/*.c -I benchmarks/mempool -lc -fno-sanitize-c --name mempool -O ReleaseFast

info(btree): insert: 477.383ms
info(btree): search: 425.205ms
info(btree): delete: 474.398ms
info(red_black_tree): insert: 689.203ms
info(red_black_tree): search: 648.113ms
info(red_black_tree): skipping delete...
info(binary_heap): insert: 62.174ms
info(binary_heap): skipping search/delete...
info(skiplist): insert: 1.482s
info(skiplist): skipping search/delete...
info(libart): insert: 146.589ms
info(libart): search: 79.467ms
info(libart): delete: 212.199ms
info(art_travis): insert: 195.397ms
info(art_travis): search: 85.063ms
info(art_travis): delete: 197.009ms
info(art): insert: 177.603ms
info(art): search: 170.312ms
info(art): delete: 195.265ms
info(rax): insert: 469.846ms
info(rax): search: 319.035ms
info(rax): delete: 562.638ms
```