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