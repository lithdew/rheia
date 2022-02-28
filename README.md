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

Rheia requires Zig nightly and an up-to-date Linux kernel (>= v5.13).

### rheia

- Update the `zig-sqlite` submodule

```console
$ git submodule update --init --recursive
```

- Build rheia

```console
$ zig build -Drelease-fast

$ zig-out/bin/rheia --help
rheia

Usage:
  rheia [options] [--] ([<host>][:]<port>)...
  rheia -h | --help
  rheia --version

Arguments:
  ([<host>][:]<port>...)                    List of peer addresses to bootstrap with.

Options:
  -h, --help                                Show this screen.
  -v, --version                             Show version.
  -d, --database-path                       File path for storing all state and data. (env: DB_PATH)
  -l, --listen-address ([<host>][:]<port>)  Address to listen for peers on. (env: LISTEN_ADDR) [default: 0.0.0.0:9000]
  -b, --http-address ([<host>][:]<port>)    Address to handle HTTP requests on. (env: HTTP_ADDR) [default: 0.0.0.0:8080]
  -n, --node-address ([<host>][:]<port>)    Address for peers to reach this node on. (env: NODE_ADDR) [default: --listen-address]
  -s, --secret-key <secret key>             Hex-encoded Ed25519 secret key of this node. (env: SECRET_KEY) [default: randomly generated]

To spawn and bootstrap a three-node Rheia cluster:
  rheia -l 9000
  rheia -l 9001 127.0.0.1:9000
  rheia -l 9002 127.0.0.1:9000
```

### benchmark tool

Rheia comes with a benchmark tool which creates, signs, and submits no-op transactions to 127.0.0.1:9000.

```console
$ zig-out/bin/rheia_bench
debug(main): public key: e29b474107bb2d19a8e4f3d0d6d0ccca54a0d8c21859761faa8d0913c375c26f
debug(main): secret key: d2f1a365520ea9f3f57ee804ccdba9b159238d1a0efa5da0c6af2b2343737c1e
info(main): sending transactions to 127.0.0.1:9000...
debug(runtime): event loop started
debug(client): 127.0.0.1:9000 [0] was spawned
debug(client): 127.0.0.1:9000 [0] successfully established a connection
debug(client): 127.0.0.1:9000 [1] was spawned
debug(client): 127.0.0.1:9000 [1] successfully established a connection
debug(client): 127.0.0.1:9000 [2] was spawned
debug(client): 127.0.0.1:9000 [2] successfully established a connection
debug(client): 127.0.0.1:9000 [3] was spawned
debug(client): 127.0.0.1:9000 [3] successfully established a connection
info(benchmark): created and sent 2902 transaction(s)
info(benchmark): created and sent 2386 transaction(s)
info(benchmark): created and sent 2435 transaction(s)
info(benchmark): created and sent 2253 transaction(s)
info(benchmark): created and sent 2345 transaction(s)
```

## usage

Rheia nodes by default expose a HTTP API on port 8080 which developers may utilize to submit new transactions and paginate through finalized blocks/transactions/state.

### GET /

Returns information about the node.

#### Example Response

```json
{
  "id": {
    "public_key": "b8ee110264e3dc812e43148db913bdf2b7e25b1752cab1c987f9b9a649069837",
    "address": "172.31.46.205:9000"
  },
  "database_path": "/home/ec2-user/efs/node_1.db",
  "current_block_height": 0,
  "num_pending_transactions": 0,
  "num_missing_transactions": 0,
  "peer_ids": [
    {
      "public_key": "16b8471e91f9134f281410df4de031083fd5b93d79cb0a12f79c68c16393dae2",
      "address": "172.31.46.205:9001"
    }
  ]
}
```

### GET /blocks

List, query, and filter through finalized blocks of transactions. Parameters are specified through URL query parameters. If no parameters are specified, the last 100 most recent finalized blocks are provided.

#### Parameters

1. id: Not required. Hex-encoded block ID. Must be 64 characters.
2. height: Not required. Block height.
3. offset: Not required. Pagination offset.
4. limit: Not required. Pagination limit.

### GET /transactions

List, query, and filter through finalized transactions. Parameters are specified through URL query parameters. If no parameters are specified, the last 100 most recent finalized transactions are returned.

#### Parameters

1. id: Not required. Hex-encoded transaction ID. Must be 64 characters.
2. block_height: Not required. Filter for transactions that have been finalized at a specified block height.
3. offset: Not required. Pagination offset.
4. limit: Not required. Pagination limit.

### GET /database/{query}

Execute a read-only SQL query against the nodes' latest state.

### POST /transactions

Submit a new transaction. The transaction's contents is expected to be in the HTTP request's body in binary format. If there are no public keys previously whitelisted, then transactions may be freely submitted by any user. Otherwise, only transactions created by whitelisted users may be submitted. The binary format of a transaction is as follows:

| Name              | Size        | Description                                                                                                                                                                                                                   |
| ----------------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Sender Public Key | 32 bytes    | The public key of the creator of the transaction.                                                                                                                                                                             |
| Signature         | 64 bytes    | An Ed25519 signature of the transaction's contents. The transaction's contents is denoted to be all bytes after the 'data length' transaction field.                                                                          |
| Data Length       | 4 bytes     | An unsigned 32-bit little-endian integer denoting the total number of bytes that make up the 'data' transaction field.                                                                                                        |
| Sender Nonce      | 8 bytes     | An unsigned 64-bit little-endian integer which may be randomly generated to prevent transactions with identical fields from yielding the same cryptographic ID.                                                               |
| Created At        | 8 bytes     | An unsigned 64-bit little-endian integer denoting the last-known block height the creator of the transaction is aware of. Ignored for the time being.                                                                         |
| Tag               | 1 byte      | An unsigned 8-bit little-endian integer denoting what operation this transaction is meant to perform. A tag of 0 denotes a no-op transaction. A tag of 1 denotes a write-only SQL transaction which mutates blockchain state. |
| Data              | Data Length | If the 'tag' transaction field is 0, then 'data' is nothing. If the 'tag' transaction field is 1, then 'data' is a write-only SQL statement that is to be executed once this transaction is finalized.                        |

### PUT /whitelist

Whitelists a public key. If there are no public keys previously whitelisted, then no whitelist is enforced. Otherwise, the user that makes this request must have been previously whitelisted.

| Name              | Description                                                                                                          |
| ----------------- | -------------------------------------------------------------------------------------------------------------------- |
| public_key        | The public key that was used to sign this request in hex.                                                            |
| signature         | An Ed25519 signature of 'timestamp' encoded as a little-endian signed 64-bit integer in hex.                         |
| target_public_key | The public key that is to be whitelisted.                                                                            |
| timestamp         | A Unix timestamp in seconds. The timestamp must not be older than 10 minutes, or 10 minutes farther into the future. |

### DELETE /whitelist

Removes a public key from the whitelist. If there are no public keys previously whitelisted, then no whitelist is enforced. Otherwise, the user that makes this request must have been previously whitelisted.

| Name              | Description                                                                                                          |
| ----------------- | -------------------------------------------------------------------------------------------------------------------- |
| public_key        | The public key that was used to sign this request in hex.                                                            |
| signature         | An Ed25519 signature of 'timestamp' encoded as a little-endian signed 64-bit integer in hex.                         |
| target_public_key | The public key that is to be removed from the whitelist.                                                             |
| timestamp         | A Unix timestamp in seconds. The timestamp must not be older than 10 minutes, or 10 minutes farther into the future. |

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

```console
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
2. B-Tree ([tidwall/btree.c](https://github.com/tidwall/btree.c))
3. Adaptive Radix Tree ([armon/libart](https://github.com/armon/libart))
4. Skiplist ([MauriceGit/skiplist](https://github.com/MauriceGit/skiplist) - ported to [zig](benchmarks/mempool/skiplist.zig))
5. Red-black Tree ([ziglang/std-lib-orphanage](https://github.com/ziglang/std-lib-orphanage/blob/master/std/rb.zig))
6. Radix Tree ([antirez/rax](https://github.com/antirez/rax) - ported to [zig](benchmarks/mempool/rax.zig))
7. Binary Heap ([ziglang/zig](https://github.com/ziglang/zig/blob/master/lib/std/priority_queue.zig))
8. Adaptive Radix Tree ([armon/libart](https://github.com/armon/libart) - ported to [zig](benchmarks/mempool/art.zig))
9. Adaptive Radix Tree ([travisstaloch/art.zig](https://github.com/travisstaloch/art.zig))

The robin hood hash table showed the highest average overall throughput over the following tests:

1. Insert 1 million different hashes into the data structure.
2. Check if 1 million different hashes exist in the data structure.
3. Delete 1 million different hashes from the data structure.

Using the robin hood hash table with a max load factor of 50%, roughly:

1. 19.58 million transactions can be indexed per second.
2. 25.07 million transactions can be searched for by their ID per second.
3. 20.91 million transactions can be searched for and unindexed by their ID per second.

The benchmark code is available [here](benchmarks/mempool/main.zig). An example run is provided below.

```console
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
