const std = @import("std");
const net = @import("net.zig");
const lru = @import("lru.zig");
const sync = @import("sync.zig");
const crypto = @import("crypto.zig");
const runtime = @import("runtime.zig");

const io = std.io;
const os = std.os;
const ip = std.x.net.ip;
const fmt = std.fmt;
const mem = std.mem;
const tcp = std.x.net.tcp;
const math = std.math;
const meta = std.meta;
const time = std.time;
const testing = std.testing;

const IPv4 = std.x.os.IPv4;
const IPv6 = std.x.os.IPv6;
const Context = runtime.Context;
const Atomic = std.atomic.Atomic;
const Blake3 = std.crypto.hash.Blake3;
const Ed25519 = std.crypto.sign.Ed25519;
const HashMap = @import("hash_map.zig").HashMap;
const SinglyLinkedList = @import("intrusive.zig").SinglyLinkedList;

const assert = std.debug.assert;

pub const log_level = .debug;

pub fn main() !void {
    const log = std.log.scoped(.main);

    try runtime.init();
    defer runtime.deinit();

    var frame = async run();
    defer nosuspend await frame catch |err| log.warn("{}", .{err});

    try runtime.run();
}

pub fn run() !void {
    const log = std.log.scoped(.main);

    defer runtime.shutdown();

    log.info("press ctrl+c to commence graceful shutdown", .{});

    var ctx: Context = .{};
    defer ctx.cancel();

    var listener = try tcp.Listener.init(.ip, .{ .close_on_exec = true });
    defer listener.deinit();

    try listener.setReuseAddress(true);
    try listener.setReusePort(true);
    try listener.setFastOpen(true);

    try listener.bind(ip.Address.initIPv4(IPv4.localhost, 9000));
    try listener.listen(128);

    const keys = try Ed25519.KeyPair.create(null);
    log.debug("public key: {}", .{fmt.fmtSliceHexLower(&keys.public_key)});
    log.debug("secret key: {}", .{fmt.fmtSliceHexLower(keys.secret_key[0..Ed25519.seed_length])});

    var node: Node = undefined;
    try node.init(runtime.getAllocator(), keys, try listener.getLocalAddress());
    defer {
        var shutdown_ctx: Context = .{};
        defer shutdown_ctx.cancel();

        node.deinit(&shutdown_ctx, runtime.getAllocator());
    }

    var node_frame = async node.run(&ctx, runtime.getAllocator());
    defer await node_frame catch |err| log.warn("node error: {}", .{err});

    var server = net.Server(Node).init(&node);
    defer {
        var shutdown_ctx: Context = .{};
        defer shutdown_ctx.cancel();

        if (server.deinit(&shutdown_ctx)) |_| {
            log.info("server successfully shut down", .{});
        } else |err| {
            log.warn("server reported an error while shutting down: {}", .{err});
        }
    }

    var server_frame = async server.serve(&ctx, runtime.getAllocator(), listener);
    defer await server_frame catch |err| log.warn("server error: {}", .{err});

    var stats_frame = async reportStatistics(&ctx);
    defer await stats_frame catch |err| log.warn("stats error: {}", .{err});

    {
        // TODO: remove this when peer bootstrapping is implemented
        const client_address = ip.Address.initIPv4(IPv4.localhost, 9000);
        const client = try node.getOrCreateClient(&ctx, runtime.getAllocator(), client_address);
        try client.ensureConnectionAvailable(&ctx, runtime.getAllocator());
    }

    runtime.waitForSignal(&ctx, .{os.SIGINT}) catch {};
    log.info("gracefully shutting down...", .{});

    ctx.cancel();
}

var finalized_count: Atomic(u64) = .{ .value = 0 };
var pusher_count: Atomic(u64) = .{ .value = 0 };
var pusher_bytes: Atomic(u64) = .{ .value = 0 };

pub fn reportStatistics(ctx: *Context) !void {
    const log = std.log.scoped(.stats);

    while (true) {
        try runtime.timeout(ctx, .{ .nanoseconds = 1 * time.ns_per_s });

        log.info("finalized(tx): {}, pushed(tx): {}, pushed(bytes(tx)): {}", .{
            finalized_count.swap(0, .Monotonic),
            pusher_count.swap(0, .Monotonic),
            fmt.fmtIntSizeBin(pusher_bytes.swap(0, .Monotonic)),
        });
    }
}

pub const ID = struct {
    pub const header_size = @sizeOf([32]u8);

    public_key: [32]u8,
    address: ip.Address,

    pub fn size(self: ID) u32 {
        return ID.header_size + @sizeOf(u8) + @as(u32, switch (self.address) {
            .ipv4 => @sizeOf([4]u8),
            .ipv6 => @sizeOf([16]u8) + @sizeOf(u32),
        }) + @sizeOf(u16);
    }

    pub fn write(self: ID, writer: anytype) !void {
        try writer.writeAll(&self.public_key);
        try writer.writeByte(@enumToInt(self.address));
        switch (self.address) {
            .ipv4 => |info| {
                try writer.writeAll(&info.host.octets);
                try writer.writeIntLittle(u16, info.port);
            },
            .ipv6 => |info| {
                try writer.writeAll(&info.host.octets);
                try writer.writeIntLittle(u32, info.host.scope_id);
                try writer.writeIntLittle(u16, info.port);
            },
        }
    }

    pub fn read(reader: anytype) !ID {
        var id: ID = undefined;
        id.public_key = try reader.readBytesNoEof(32);

        switch (try meta.intToEnum(meta.Tag(ip.Address), try reader.readByte())) {
            .ipv4 => {
                const host = IPv4{ .octets = try reader.readBytesNoEof(4) };
                const port = try reader.readIntLittle(u16);
                id.address = ip.Address.initIPv4(host, port);
            },
            .ipv6 => {
                const host = IPv6{
                    .octets = try reader.readBytesNoEof(16),
                    .scope_id = try reader.readIntLittle(u32),
                };
                const port = try reader.readIntLittle(u16);
                id.address = ip.Address.initIPv6(host, port);
            },
        }

        return id;
    }

    pub fn format(self: ID, comptime layout: []const u8, options: fmt.FormatOptions, writer: anytype) !void {
        _ = layout;
        _ = options;
        try fmt.format(writer, "{}[{}]", .{ self.address, fmt.fmtSliceHexLower(&self.public_key) });
    }
};

pub const Block = struct {
    pub const header_size = @sizeOf(u64) + @sizeOf([32]u8) + @sizeOf(u16);
    pub const max_num_transaction_ids: u16 = math.maxInt(u16);

    pub const Params = struct {
        height: u64,
        merkle_root: [32]u8,
        transaction_ids: []const [32]u8,
    };

    id: [32]u8,
    refs: usize = 1,

    height: u64,
    merkle_root: [32]u8,
    num_transaction_ids: u16,
    transaction_ids: [*][32]u8,

    pub fn create(gpa: *mem.Allocator, params: Block.Params) !*Block {
        const bytes_len = @sizeOf(Block) + params.transaction_ids.len * @sizeOf([32]u8);
        const bytes = try gpa.alignedAlloc(u8, @alignOf(Block), bytes_len);
        errdefer gpa.free(bytes);

        const block = @ptrCast(*Block, bytes.ptr);

        block.refs = 1;
        block.height = params.height;
        block.merkle_root = params.merkle_root;
        block.num_transaction_ids = @intCast(u16, params.transaction_ids.len);

        block.transaction_ids = @ptrCast([*][32]u8, bytes.ptr + @sizeOf(Block));
        mem.copy([32]u8, block.transaction_ids[0..block.num_transaction_ids], params.transaction_ids);

        // blake3 id

        var hash = crypto.HashWriter(Blake3).wrap(Blake3.init(.{}));
        try block.write(hash.writer());
        block.id = hash.digest(32);

        return block;
    }

    pub fn deinit(self: *Block, gpa: *mem.Allocator) void {
        self.refs -= 1;
        if (self.refs == 0) {
            const bytes_len = @sizeOf(Block) + @as(usize, self.num_transaction_ids) * @sizeOf([32]u8);
            gpa.free(@ptrCast([*]const u8, self)[0..bytes_len]);
        }
    }

    pub fn ref(self: *Block) *Block {
        assert(self.refs >= 1);
        self.refs += 1;
        return self;
    }

    pub fn write(self: Block, writer: anytype) !void {
        try writer.writeIntLittle(u64, self.height);
        try writer.writeAll(&self.merkle_root);
        try writer.writeIntLittle(u16, self.num_transaction_ids);
        try writer.writeAll(mem.sliceAsBytes(self.transaction_ids[0..self.num_transaction_ids]));
    }

    pub fn size(self: Block) u32 {
        return Block.header_size + @as(u32, self.num_transaction_ids) * @sizeOf([32]u8);
    }

    pub fn read(gpa: *mem.Allocator, reader: anytype) !*Block {
        var block = try gpa.create(Block);
        errdefer gpa.destroy(block);

        block.height = try reader.readIntLittle(u64);
        block.merkle_root = try reader.readBytesNoEof(32);
        block.num_transaction_ids = try reader.readIntLittle(u16);
        if (block.num_transaction_ids == 0) return error.NoTransactionIds;

        const bytes_len = @sizeOf(Block) + @as(usize, block.num_transaction_ids) * @sizeOf([32]u8);
        block = @ptrCast(*Block, try gpa.realloc(mem.span(mem.asBytes(block)), bytes_len));

        block.transaction_ids = @ptrCast([*][32]u8, @ptrCast([*]u8, block) + @sizeOf(Block));
        try reader.readNoEof(mem.sliceAsBytes(block.transaction_ids[0..block.num_transaction_ids]));

        var hash = crypto.HashWriter(Blake3).wrap(Blake3.init(.{}));
        try block.write(hash.writer());
        block.id = hash.digest(32);

        block.refs = 1;

        return block;
    }
};

pub const Transaction = struct {
    pub const header_size = @sizeOf([32]u8) + @sizeOf([64]u8) + @sizeOf(u32) + @sizeOf(u64) + @sizeOf(u64) + @sizeOf(Transaction.Tag);

    pub const Tag = enum(u8) {
        no_op,
    };

    pub const Params = struct {
        sender_nonce: u64,
        created_at: u64,
        tag: Tag,
        data: []const u8,
    };

    id: [32]u8,
    refs: usize = 1,

    sender: [32]u8,
    signature: [64]u8,
    data_len: u32,

    sender_nonce: u64,
    created_at: u64,
    tag: Tag,
    data: [*]u8,

    pub fn create(gpa: *mem.Allocator, keys: Ed25519.KeyPair, params: Transaction.Params) !*Transaction {
        const bytes = try gpa.alignedAlloc(u8, @alignOf(Transaction), @sizeOf(Transaction) + params.data.len);
        errdefer gpa.free(bytes);

        const tx = @ptrCast(*Transaction, bytes.ptr);

        tx.refs = 1;
        tx.sender = keys.public_key;
        tx.data_len = @intCast(u32, params.data.len);

        tx.sender_nonce = params.sender_nonce;
        tx.created_at = params.created_at;
        tx.tag = params.tag;

        tx.data = bytes.ptr + @sizeOf(Transaction);
        mem.copy(u8, tx.data[0..tx.data_len], params.data);

        // ed25519 signature

        tx.signature = try crypto.sign(tx, keys);

        // blake3 id

        var hash = crypto.HashWriter(Blake3).wrap(Blake3.init(.{}));
        try tx.write(hash.writer());
        tx.id = hash.digest(32);

        return tx;
    }

    pub fn deinit(self: *Transaction, gpa: *mem.Allocator) void {
        self.refs -= 1;
        if (self.refs == 0) {
            gpa.free(@ptrCast([*]const u8, self)[0 .. @sizeOf(Transaction) + self.data_len]);
        }
    }

    pub fn ref(self: *Transaction) *Transaction {
        assert(self.refs >= 1);
        self.refs += 1;
        return self;
    }

    pub fn write(self: Transaction, writer: anytype) !void {
        try writer.writeAll(&self.sender);
        try writer.writeAll(&self.signature);
        try writer.writeIntLittle(u32, self.data_len);
        try self.writeSignaturePayload(writer);
    }

    pub fn writeSignaturePayload(self: Transaction, writer: anytype) !void {
        try writer.writeIntLittle(u64, self.sender_nonce);
        try writer.writeIntLittle(u64, self.created_at);
        try writer.writeIntLittle(u8, @enumToInt(self.tag));
        try writer.writeAll(self.data[0..self.data_len]);
    }

    pub fn size(self: Transaction) u32 {
        return Transaction.header_size + self.data_len;
    }

    pub fn read(gpa: *mem.Allocator, reader: anytype) !*Transaction {
        var tx = try gpa.create(Transaction);
        errdefer gpa.destroy(tx);

        tx.sender = try reader.readBytesNoEof(32);
        tx.signature = try reader.readBytesNoEof(64);
        tx.data_len = try reader.readIntLittle(u32);
        if (tx.data_len > 65536) return error.TransactionTooLarge;

        tx = @ptrCast(*Transaction, try gpa.realloc(mem.span(mem.asBytes(tx)), @sizeOf(Transaction) + tx.data_len));
        tx.sender_nonce = try reader.readIntLittle(u64);
        tx.created_at = try reader.readIntLittle(u64);
        tx.tag = try reader.readEnum(Transaction.Tag, .Little);

        tx.data = @ptrCast([*]u8, tx) + @sizeOf(Transaction);
        try reader.readNoEof(tx.data[0..tx.data_len]);

        var hash = crypto.HashWriter(Blake3).wrap(Blake3.init(.{}));
        try tx.write(hash.writer());
        tx.id = hash.digest(32);

        tx.refs = 1;

        return tx;
    }
};

test "id: serialize and deserialize" {
    var seed: usize = 0;
    while (seed < 128) : (seed += 1) {
        var rng = std.rand.DefaultPrng.init(seed);

        var public_key: [32]u8 = undefined;
        rng.random.bytes(&public_key);

        const address = address: {
            switch (rng.random.boolean()) {
                true => {
                    var host_octets: [4]u8 = undefined;
                    rng.random.bytes(&host_octets);

                    const host = IPv4{ .octets = host_octets };
                    const port = rng.random.int(u16);
                    break :address ip.Address.initIPv4(host, port);
                },
                false => {
                    var host_octets: [16]u8 = undefined;
                    rng.random.bytes(&host_octets);

                    const host = IPv6{ .octets = host_octets, .scope_id = rng.random.int(u32) };
                    const port = rng.random.int(u16);
                    break :address ip.Address.initIPv6(host, port);
                },
            }
        };

        const expected: ID = .{ .public_key = public_key, .address = address };

        var data = std.ArrayList(u8).init(testing.allocator);
        defer data.deinit();

        try expected.write(data.writer());

        const actual = try ID.read(io.fixedBufferStream(data.items).reader());

        try testing.expectEqual(expected, actual);
    }
}

test "block: create, serialize, and deserialize" {
    const expected = try Block.create(testing.allocator, .{
        .height = 123,
        .merkle_root = [_]u8{1} ** 32,
        .transaction_ids = &[_][32]u8{ [_]u8{2} ** 32, [_]u8{3} ** 32, [_]u8{4} ** 32 },
    });
    defer expected.deinit(testing.allocator);

    var data = std.ArrayList(u8).init(testing.allocator);
    defer data.deinit();

    try expected.write(data.writer());

    const actual = try Block.read(testing.allocator, io.fixedBufferStream(data.items).reader());
    defer actual.deinit(testing.allocator);

    try testing.expectEqual(expected.height, actual.height);
    try testing.expectEqual(expected.merkle_root, actual.merkle_root);
    try testing.expectEqual(expected.num_transaction_ids, actual.num_transaction_ids);

    try testing.expectEqualSlices(
        [32]u8,
        expected.transaction_ids[0..expected.num_transaction_ids],
        actual.transaction_ids[0..actual.num_transaction_ids],
    );
}

test "transaction: create, serialize, and deserialize" {
    const keys = try Ed25519.KeyPair.create(null);

    const expected = try Transaction.create(testing.allocator, keys, .{
        .sender_nonce = 123,
        .created_at = 456,
        .tag = .no_op,
        .data = "hello world",
    });
    defer expected.deinit(testing.allocator);

    var data = std.ArrayList(u8).init(testing.allocator);
    defer data.deinit();

    try expected.write(data.writer());

    const actual = try Transaction.read(testing.allocator, io.fixedBufferStream(data.items).reader());
    defer actual.deinit(testing.allocator);

    try testing.expectEqualSlices(u8, &expected.id, &actual.id);
    try testing.expectEqualSlices(u8, &expected.sender, &actual.sender);
    try testing.expectEqual(expected.data_len, actual.data_len);
    try testing.expectEqual(expected.sender_nonce, actual.sender_nonce);
    try testing.expectEqual(expected.created_at, actual.created_at);
    try testing.expectEqual(expected.tag, actual.tag);
    try testing.expectEqualStrings(expected.data[0..expected.data_len], actual.data[0..expected.data_len]);
}

pub const Node = struct {
    const log = std.log.scoped(.node);

    id: ID,
    keys: Ed25519.KeyPair,

    chain: Chain,
    pusher: TransactionPusher,
    puller: TransactionPuller,
    verifier: TransactionVerifier,
    clients: std.HashMapUnmanaged(ip.Address, *net.Client, struct {
        pub fn hash(_: @This(), address: ip.Address) u64 {
            var hasher = std.hash.Wyhash.init(0);
            switch (address) {
                .ipv4 => |ipv4| {
                    hasher.update(&ipv4.host.octets);
                    hasher.update(mem.asBytes(&ipv4.port));
                },
                .ipv6 => |ipv6| {
                    hasher.update(&ipv6.host.octets);
                    hasher.update(mem.asBytes(&ipv6.host.scope_id));
                    hasher.update(mem.asBytes(&ipv6.port));
                },
            }
            return hasher.final();
        }

        pub fn eql(_: @This(), a: ip.Address, b: ip.Address) bool {
            switch (a) {
                .ipv4 => {
                    if (b != .ipv4) return false;
                    if (a.ipv4.port != b.ipv4.port) return false;
                    if (!a.ipv4.host.eql(b.ipv4.host)) return false;
                },
                .ipv6 => {
                    if (b != .ipv6) return false;
                    if (a.ipv6.port != b.ipv6.port) return false;
                    if (!a.ipv6.host.eql(b.ipv6.host)) return false;
                },
            }
            return true;
        }
    }, std.hash_map.default_max_load_percentage),
    closed: bool = false,

    pub fn init(self: *Node, gpa: *mem.Allocator, keys: Ed25519.KeyPair, address: ip.Address) !void {
        self.keys = keys;
        self.id = ID{ .public_key = keys.public_key, .address = address };

        self.chain = try Chain.init(gpa);
        errdefer self.chain.deinit(gpa);

        self.pusher = try TransactionPusher.init(gpa, self);
        self.puller = TransactionPuller.init(self);
        self.verifier = TransactionVerifier.init(self);

        self.clients = .{};
    }

    pub fn deinit(self: *Node, ctx: *Context, gpa: *mem.Allocator) void {
        log.info("shutting down...", .{});

        self.closed = true;

        var client_it = self.clients.valueIterator();
        while (client_it.next()) |client_ptr| {
            log.info("shutting down client {}...", .{client_ptr.*.address});

            if (client_ptr.*.deinit(gpa, ctx)) |_| {
                log.info("client {} successfully shut down", .{client_ptr.*.address});
            } else |err| {
                log.warn("client {} reported an error while shutting down: {}", .{ client_ptr.*.address, err });
            }

            gpa.destroy(client_ptr.*);
        }
        self.clients.deinit(gpa);

        self.verifier.deinit(ctx, gpa);
        self.puller.deinit();
        self.pusher.deinit(ctx, gpa);
        self.chain.deinit(gpa);

        log.info("successfully shut down", .{});
    }

    pub fn getOrCreateClient(self: *Node, ctx: *Context, gpa: *mem.Allocator, address: ip.Address) !*net.Client {
        if (self.closed) return error.Closed;

        const result = try self.clients.getOrPut(gpa, address);
        if (!result.found_existing) {
            errdefer assert(self.clients.remove(address));

            result.value_ptr.* = try gpa.create(net.Client);
            errdefer gpa.destroy(result.value_ptr.*);

            result.value_ptr.*.* = try net.Client.init(gpa, address);
            errdefer result.value_ptr.*.deinit(gpa, ctx) catch {};

            try result.value_ptr.*.ensureConnectionAvailable(ctx, gpa);

            var entry: net.Client.RPC.Entry = .{};
            var nonce = try result.value_ptr.*.rpc.register(ctx, &entry);

            {
                const writer = try result.value_ptr.*.acquireWriter(ctx, gpa);
                defer result.value_ptr.*.releaseWriter(writer);

                try (net.Packet{
                    .len = self.id.size(),
                    .nonce = nonce,
                    .op = .request,
                    .tag = .hello,
                }).write(writer);

                try self.id.write(writer);
            }

            const response = try await entry.response;
            defer response.deinit(gpa);

            var body = io.fixedBufferStream(response.body);

            const peer_id = try ID.read(body.reader());
            log.info("handshaked with {}", .{peer_id});
        }

        return result.value_ptr.*;
    }

    pub fn acquireWriter(self: *Node, ctx: *Context, gpa: *mem.Allocator, address: ip.Address) !std.ArrayList(u8).Writer {
        const client = try self.getOrCreateClient(ctx, gpa, address);
        return client.acquireWriter(ctx, gpa);
    }

    pub fn releaseWriter(self: *Node, address: ip.Address, writer: std.ArrayList(u8).Writer) void {
        const client = self.clients.get(address) orelse unreachable;
        return client.releaseWriter(writer);
    }

    pub fn run(self: *Node, ctx: *Context, gpa: *mem.Allocator) !void {
        var pusher_frame = async self.pusher.run(ctx, gpa);
        defer await pusher_frame catch |err| if (err != error.Cancelled) log.warn("transaction pusher error: {}", .{err});

        var puller_frame = async self.puller.run(ctx, gpa);
        defer await puller_frame catch |err| if (err != error.Cancelled) log.warn("transaction puller error: {}", .{err});

        var verifier_frame = async self.verifier.run(ctx, gpa);
        defer await verifier_frame catch |err| if (err != error.Cancelled) log.warn("transaction verifier error: {}", .{err});

        var chain_frame = async self.chain.run(ctx, gpa, self);
        defer await chain_frame catch |err| if (err != error.Cancelled) log.warn("chain error: {}", .{err});
    }

    pub fn addTransaction(self: *Node, ctx: *Context, gpa: *mem.Allocator, tx: *Transaction) !void {
        const result = self.chain.pending.getOrPutAssumeCapacity(tx.id);
        if (result.found_existing) {
            return error.AlreadyExists;
        }
        result.value_ptr.* = tx;

        _ = self.chain.missing.delete(tx.id);

        self.pusher.push(ctx, gpa, tx.ref()) catch |err| {
            tx.deinit(gpa);
            return err;
        };
    }

    pub fn handleServerPacket(
        self: *Node,
        ctx: *Context,
        gpa: *mem.Allocator,
        conn: *net.Server(Node).Connection,
        packet: net.Packet,
        frame: anytype,
    ) !void {
        switch (packet.op) {
            .request => {
                switch (packet.tag) {
                    .ping => {
                        try (net.Packet{
                            .len = "hello world".len,
                            .nonce = packet.nonce,
                            .op = .response,
                            .tag = .ping,
                        }).write(conn.buffer.writer());

                        try conn.buffer.writer().writeAll("hello world");

                        conn.writer_parker.notify({});
                    },
                    .hello => {
                        const peer_id = try ID.read(frame.reader());
                        log.info("incoming handshake from {}", .{peer_id});

                        try (net.Packet{
                            .len = self.id.size(),
                            .nonce = packet.nonce,
                            .op = .response,
                            .tag = .hello,
                        }).write(conn.buffer.writer());

                        try self.id.write(conn.buffer.writer());

                        conn.writer_parker.notify({});
                    },
                    .pull_transaction => {
                        var transactions: std.ArrayListUnmanaged(*Transaction) = .{};
                        defer transactions.deinit(gpa);

                        var num_bytes: u32 = 0;
                        while (true) {
                            const tx_id = frame.reader().readBytesNoEof(32) catch |err| switch (err) {
                                error.EndOfStream => break,
                                else => return err,
                            };

                            const tx = self.chain.pending.get(tx_id) orelse continue;
                            try transactions.append(gpa, tx);
                            num_bytes += tx.size();
                        }

                        try (net.Packet{
                            .len = num_bytes,
                            .nonce = packet.nonce,
                            .op = .response,
                            .tag = .pull_transaction,
                        }).write(conn.buffer.writer());

                        for (transactions.items) |tx| {
                            try tx.write(conn.buffer.writer());
                        }

                        conn.writer_parker.notify({});
                    },
                    .pull_block => {
                        const requested_height = try frame.reader().readIntLittle(u64);
                        const latest_height = if (self.chain.blocks.latest()) |latest_block| latest_block.height else 0;

                        const requested_block = block: {
                            if (requested_height == latest_height + 1) {
                                break :block self.chain.sampler.preferred;
                            }
                            if (self.chain.blocks.get(requested_height)) |old_block| {
                                break :block old_block;
                            }
                            break :block null;
                        };

                        const cache_hit = cache_hit: {
                            const cache_id = frame.reader().readBytesNoEof(32) catch break :cache_hit false;
                            const block = requested_block orelse break :cache_hit false;
                            if (!mem.eql(u8, &block.id, &cache_id)) {
                                break :cache_hit false;
                            }
                            break :cache_hit true;
                        };

                        try (net.Packet{
                            .len = 1 + (if (requested_block) |block| if (!cache_hit) block.size() else 0 else 0),
                            .nonce = packet.nonce,
                            .op = .response,
                            .tag = .pull_block,
                        }).write(conn.buffer.writer());

                        if (requested_block) |block| {
                            try conn.buffer.writer().writeByte(1);
                            if (!cache_hit) {
                                try block.write(conn.buffer.writer());
                            }
                        } else {
                            try conn.buffer.writer().writeByte(0);
                        }

                        conn.writer_parker.notify({});
                    },
                    else => return error.UnexpectedTag,
                }
            },
            .command => {
                switch (packet.tag) {
                    .ping => {
                        try (net.Packet{
                            .len = "hello world".len,
                            .nonce = 0,
                            .op = .command,
                            .tag = .ping,
                        }).write(conn.buffer.writer());

                        try conn.buffer.writer().writeAll("hello world");

                        conn.writer_parker.notify({});
                    },
                    .push_transaction => {
                        var count: usize = 0;
                        while (true) : (count += 1) {
                            const tx = Transaction.read(gpa, frame.reader()) catch |err| switch (err) {
                                error.EndOfStream => break,
                                else => return err,
                            };
                            errdefer tx.deinit(gpa);

                            try self.verifier.push(ctx, gpa, tx);
                        }
                    },
                    else => return error.UnexpectedTag,
                }
            },
            .response => return error.UnexpectedPacket,
        }
    }
};

pub const Chain = struct {
    const log = std.log.scoped(.chain);

    const BlockProposalMap = std.HashMapUnmanaged(
        ?*Block,
        usize,
        struct {
            pub fn hash(_: @This(), maybe_block: ?*Block) u64 {
                const block = maybe_block orelse return 0;
                return mem.readIntNative(u64, block.id[0..8]);
            }
            pub fn eql(_: @This(), maybe_block_a: ?*Block, maybe_block_b: ?*Block) bool {
                const block_a = maybe_block_a orelse return maybe_block_b == null;
                const block_b = maybe_block_b orelse return false;
                return mem.eql(u8, &block_a.id, &block_b.id);
            }
        },
        std.hash_map.default_max_load_percentage,
    );

    pub const propose_delay_min: i64 = 0 * time.ns_per_ms;
    pub const propose_delay_max: i64 = 500 * time.ns_per_ms;

    pub const connected_delay_min: i64 = 0 * time.ns_per_ms;
    pub const connected_delay_max: i64 = 500 * time.ns_per_ms;

    sampler: Sampler,
    pending: HashMap(*Transaction, 50),
    missing: lru.AutoIntrusiveHashMap([32]u8, u64, 50),

    blocks: BlockRingBuffer = .{},
    block_proposal_cache: lru.AutoIntrusiveHashMap(ip.Address, *Block, 50),

    propose_delay: i64 = propose_delay_min,
    connected_delay: i64 = connected_delay_min,

    pub fn init(gpa: *mem.Allocator) !Chain {
        var sampler = try Sampler.init(gpa);
        errdefer sampler.deinit(gpa);

        var pending = try HashMap(*Transaction, 50).init(gpa);
        errdefer pending.deinit(gpa);

        var missing = try lru.AutoIntrusiveHashMap([32]u8, u64, 50).initCapacity(gpa, 1024);
        errdefer missing.deinit(gpa);

        var block_proposal_cache = try lru.AutoIntrusiveHashMap(ip.Address, *Block, 50).initCapacity(gpa, 128);
        errdefer block_proposal_cache.deinit(gpa);

        return Chain{
            .sampler = sampler,
            .pending = pending,
            .missing = missing,
            .block_proposal_cache = block_proposal_cache,
        };
    }

    pub fn deinit(self: *Chain, gpa: *mem.Allocator) void {
        log.info("shutting down...", .{});

        var it = self.block_proposal_cache.head;
        while (it) |entry| : (it = entry.next) {
            entry.value.deinit(gpa);
        }
        self.block_proposal_cache.deinit(gpa);

        for (self.pending.slice()) |entry| {
            if (!entry.isEmpty()) {
                entry.value.deinit(gpa);
            }
        }
        self.pending.deinit(gpa);

        self.missing.deinit(gpa);

        while (self.blocks.pop()) |block| {
            block.deinit(gpa);
        }

        self.sampler.deinit(gpa);

        log.info("successfully shut down", .{});
    }

    pub fn run(self: *Chain, ctx: *Context, gpa: *mem.Allocator, node: *Node) !void {
        var transaction_ids: std.ArrayListUnmanaged([32]u8) = .{};
        defer transaction_ids.deinit(gpa);

        var block_proposals: BlockProposalMap = .{};
        defer block_proposals.deinit(gpa);

        var votes: std.ArrayListUnmanaged(Sampler.Vote) = .{};
        defer votes.deinit(gpa);

        while (true) {
            const preferred_block = self.sampler.preferred orelse {
                try self.proposeBlock(ctx, gpa, &transaction_ids);
                continue;
            };

            // ensure sufficient memory is available for tallying block proposals and for
            // grouping block proposals together into votes

            try votes.ensureTotalCapacity(gpa, node.clients.count() + 1);
            try block_proposals.ensureTotalCapacity(gpa, node.clients.count() + 1);

            defer {
                block_proposals.clearRetainingCapacity();
                votes.clearRetainingCapacity();
            }

            // sample block proposals proposals and tally them

            self.pullBlockProposals(ctx, gpa, node, &block_proposals, preferred_block.height) catch |err| switch (err) {
                error.NoPeersAvailable => continue,
                else => return err,
            };

            // tally our own preferred block proposal

            const result = block_proposals.getOrPutAssumeCapacity(preferred_block);
            if (!result.found_existing) {
                result.value_ptr.* = 0;
            }
            result.value_ptr.* += 1;

            // group block proposal tallies together by block id

            var blocks_it = block_proposals.iterator();
            while (blocks_it.next()) |entry| {
                const count = @intToFloat(f64, entry.value_ptr.*);
                const total = @intToFloat(f64, node.clients.count() + 1);
                votes.appendAssumeCapacity(.{ .block = entry.key_ptr.*, .tally = @divTrunc(count, total) });
            }

            // update the block sampler

            // if the block sampler concludes that a block has been finalized, mark all transactions in
            // the block by their id to have been finalized, store the block on-disk, and reset the
            // block sampler

            const finalized_block = (try self.sampler.update(gpa, votes.items)) orelse continue;
            defer {
                var it = self.block_proposal_cache.head;
                while (it) |entry| : (it = entry.next) {
                    entry.value.deinit(gpa);
                }
                self.block_proposal_cache.clear();

                self.sampler.reset(gpa);
            }

            for (finalized_block.transaction_ids[0..finalized_block.num_transaction_ids]) |tx_id| {
                const tx = self.pending.delete(tx_id) orelse unreachable;
                tx.deinit(gpa);
            }

            if (self.blocks.push(finalized_block.ref())) |evicted_block| {
                evicted_block.deinit(gpa);
            }

            _ = finalized_count.fetchAdd(finalized_block.num_transaction_ids, .Monotonic);

            // log.info("finalized block {} (height {}, {} transaction(s))", .{
            //     fmt.fmtSliceHexLower(&finalized_block.id),
            //     finalized_block.height,
            //     finalized_block.num_transaction_ids,
            // });
        }
    }

    fn proposeBlock(
        self: *Chain,
        ctx: *Context,
        gpa: *mem.Allocator,
        transaction_ids: *std.ArrayListUnmanaged([32]u8),
    ) !void {
        if (self.pending.len == 0) {
            try runtime.timeout(ctx, .{ .nanoseconds = self.propose_delay });
            self.propose_delay = math.min(propose_delay_max, self.propose_delay + (propose_delay_max - propose_delay_min) / 10);
            return;
        }

        self.propose_delay = propose_delay_min;

        try transaction_ids.ensureTotalCapacity(gpa, math.min(Block.max_num_transaction_ids, self.pending.len));
        defer transaction_ids.clearRetainingCapacity();

        for (self.pending.slice()) |entry| {
            if (!entry.isEmpty()) {
                transaction_ids.appendAssumeCapacity(entry.value.id);
                if (transaction_ids.items.len == Block.max_num_transaction_ids) {
                    break;
                }
            }
        }

        const block = try Block.create(gpa, .{
            .height = (if (self.blocks.latest()) |latest_block| latest_block.height else 0) + 1,
            .merkle_root = [_]u8{0} ** 32,
            .transaction_ids = transaction_ids.items,
        });

        self.sampler.prefer(gpa, block);

        // log.debug("proposed block {} (height {}, {} transaction(s))", .{
        //     fmt.fmtSliceHexLower(&block.id),
        //     block.height,
        //     block.num_transaction_ids,
        // });
    }

    fn pullBlockProposals(
        self: *Chain,
        ctx: *Context,
        gpa: *mem.Allocator,
        node: *Node,
        block_proposals: *BlockProposalMap,
        block_proposal_height: u64,
    ) !void {
        if (node.clients.count() == 0) {
            try runtime.timeout(ctx, .{ .nanoseconds = self.connected_delay });
            self.connected_delay = math.min(connected_delay_max, self.connected_delay + (connected_delay_max - connected_delay_min) / 10);
            return error.NoPeersAvailable;
        }

        self.connected_delay = connected_delay_min;

        const frames = try gpa.alloc(@Frame(pullBlock), node.clients.count());
        defer gpa.free(frames);

        var wg: sync.WaitGroup = .{};

        var frame_index: usize = 0;
        errdefer for (frames[0..frame_index]) |*frame| {
            _ = await frame catch continue;
        };

        var client_it = node.clients.keyIterator();
        while (client_it.next()) |address_ptr| : (frame_index += 1) {
            frames[frame_index] = async self.pullBlock(ctx, gpa, &wg, node, address_ptr.*, block_proposal_height);
        }

        try wg.wait(ctx);

        for (frames[0..frame_index]) |*frame| {
            const maybe_block_proposal = await frame catch null;

            const result = block_proposals.getOrPutAssumeCapacity(maybe_block_proposal);
            if (!result.found_existing) {
                result.value_ptr.* = 0;
            }
            result.value_ptr.* += 1;
        }
    }

    fn pullBlock(
        self: *Chain,
        ctx: *Context,
        gpa: *mem.Allocator,
        wg: *sync.WaitGroup,
        node: *Node,
        address: ip.Address,
        block_height: u64,
    ) !*Block {
        wg.add(1);
        defer wg.sub(1);

        const client = try node.getOrCreateClient(ctx, gpa, address);
        const cached_block_proposal = if (self.block_proposal_cache.get(address)) |entry| entry.value.ref() else null;

        var entry: net.Client.RPC.Entry = .{};
        var nonce = try client.rpc.register(ctx, &entry);

        {
            const writer = try client.acquireWriter(ctx, gpa);
            defer client.releaseWriter(writer);

            try (net.Packet{
                .len = @sizeOf(u64) + @as(u32, if (cached_block_proposal != null) @sizeOf([32]u8) else 0),
                .nonce = nonce,
                .op = .request,
                .tag = .pull_block,
            }).write(writer);

            try writer.writeIntLittle(u64, block_height);
            if (cached_block_proposal) |block_proposal| {
                try writer.writeAll(&block_proposal.id);
            }
        }

        const response = try await entry.response;
        defer response.deinit(gpa);

        var body = io.fixedBufferStream(response.body);

        const exists = (try body.reader().readByte()) != 0;
        if (!exists) return error.BlockNotExists;

        const block = Block.read(gpa, body.reader()) catch |err| {
            if (response.body.len > 1) {
                return err;
            }

            const block_proposal = cached_block_proposal orelse return err;

            // it is possible that our cached block proposal response may have
            // been evicted by time we reach here, so an insertion may happen
            // yet again

            switch (self.block_proposal_cache.update(address, block_proposal)) {
                .inserted => {},
                .updated => |old_block| old_block.deinit(gpa),
                .evicted => |old_entry| old_entry.value.deinit(gpa),
            }
            return block_proposal;
        };
        errdefer block.deinit(gpa);

        if (block.height != block_height) {
            return error.UnexpectedPulledBlockHeight;
        }

        var maybe_err: ?anyerror = null;

        var it = [_]u8{0} ** 32;
        for (block.transaction_ids[0..block.num_transaction_ids]) |tx_id| {
            if (!mem.lessThan(u8, &it, &tx_id)) {
                maybe_err = error.BlockProposalTransactionIdsNotSorted;
            }
            if (node.chain.pending.get(tx_id) == null) {
                _ = node.chain.missing.update(tx_id, block_height);
                if (maybe_err == null) {
                    maybe_err = error.BlockProposalContainsUnknownTransactionId;
                }
            }
            it = tx_id;
        }

        if (maybe_err) |err| {
            return err;
        }

        switch (self.block_proposal_cache.update(address, block)) {
            .inserted => {},
            .updated => |old_block| old_block.deinit(gpa),
            .evicted => |old_entry| old_entry.value.deinit(gpa),
        }

        return block;
    }
};

pub const TransactionPuller = struct {
    const log = std.log.scoped(.tx_puller);

    pub const max_num_bytes_per_batch = net.Packet.max_size - net.Packet.size;

    pub const collect_delay_min: i64 = 100 * time.ns_per_ms;
    pub const collect_delay_max: i64 = 500 * time.ns_per_ms;

    pub const connected_delay_min: i64 = 0 * time.ns_per_ms;
    pub const connected_delay_max: i64 = 500 * time.ns_per_ms;

    node: *Node,

    collect_delay: i64 = collect_delay_min,
    connected_delay: i64 = connected_delay_min,

    pub fn init(node: *Node) TransactionPuller {
        return TransactionPuller{ .node = node };
    }

    pub fn deinit(self: *TransactionPuller) void {
        _ = self;
        log.info("shutting down...", .{});
        log.info("successfully shut down", .{});
    }

    pub fn run(self: *TransactionPuller, ctx: *Context, gpa: *mem.Allocator) !void {
        while (true) {
            while (self.node.chain.missing.len == 0) {
                try runtime.timeout(ctx, .{ .nanoseconds = self.collect_delay });
                self.collect_delay = math.min(collect_delay_max, self.collect_delay * 2);
                continue;
            }

            self.collect_delay = collect_delay_min;

            while (self.node.clients.count() == 0) {
                try runtime.timeout(ctx, .{ .nanoseconds = self.connected_delay });
                self.connected_delay = math.min(connected_delay_max, self.connected_delay + (connected_delay_max - connected_delay_min) / 10);
                continue;
            }

            self.connected_delay = connected_delay_min;

            self.pullMissingTransactions(ctx, gpa) catch |err| log.warn("error while pulling: {}", .{err});
        }
    }

    pub fn pullMissingTransactions(self: *TransactionPuller, ctx: *Context, gpa: *mem.Allocator) !void {
        assert(self.node.chain.missing.len > 0);

        const ids = ids: {
            const total_num_ids = math.min(self.node.chain.missing.len, max_num_bytes_per_batch / @sizeOf([32]u8));

            var ids = try std.ArrayListUnmanaged([32]u8).initCapacity(gpa, total_num_ids);
            errdefer ids.deinit(gpa);

            var it = self.node.chain.missing.tail;
            while (it) |entry| : (it = entry.prev) {
                ids.appendAssumeCapacity(entry.key);
                self.node.chain.missing.moveToFront(entry);
                if (ids.items.len == ids.capacity) {
                    break;
                }
            }

            break :ids ids.toOwnedSlice(gpa);
        };
        defer gpa.free(ids);

        const frames = try gpa.alloc(@Frame(pullTransactionsFromPeer), self.node.clients.count());
        defer gpa.free(frames);

        var frame_index: usize = 0;
        defer for (frames[0..frame_index]) |*frame| {
            const transactions = await frame catch continue;
            defer gpa.free(transactions);

            for (transactions) |tx| {
                self.node.addTransaction(ctx, gpa, tx) catch {
                    tx.deinit(gpa);
                    continue;
                };
            }
        };

        var wg: sync.WaitGroup = .{};
        defer wg.wait(ctx) catch {};

        var it = self.node.clients.keyIterator();
        while (it.next()) |address_ptr| : (frame_index += 1) {
            frames[frame_index] = async self.pullTransactionsFromPeer(ctx, gpa, &wg, address_ptr.*, ids);
        }
    }

    pub fn pullTransactionsFromPeer(
        self: *TransactionPuller,
        ctx: *Context,
        gpa: *mem.Allocator,
        wg: *sync.WaitGroup,
        address: ip.Address,
        ids: []const [32]u8,
    ) ![]const *Transaction {
        wg.add(1);
        defer wg.sub(1);

        const client = try self.node.getOrCreateClient(ctx, gpa, address);

        var entry: net.Client.RPC.Entry = .{};
        var nonce = try client.rpc.register(ctx, &entry);

        {
            const writer = try client.acquireWriter(ctx, gpa);
            defer client.releaseWriter(writer);

            try (net.Packet{
                .len = @intCast(u32, @sizeOf([32]u8) * ids.len),
                .nonce = nonce,
                .op = .request,
                .tag = .pull_block,
            }).write(writer);

            for (ids) |id| {
                try writer.writeAll(&id);
            }
        }

        const response = try await entry.response;
        defer response.deinit(gpa);

        var body = io.fixedBufferStream(response.body);

        var transactions: std.ArrayListUnmanaged(*Transaction) = .{};
        defer transactions.deinit(gpa);

        while (true) {
            const tx = Transaction.read(gpa, body.reader()) catch |err| switch (err) {
                error.EndOfStream => break,
                else => continue,
            };

            transactions.append(gpa, tx) catch continue;
        }

        return transactions.toOwnedSlice(gpa);
    }
};

pub const TransactionPusher = struct {
    const log = std.log.scoped(.tx_pusher);

    const Cache = lru.IntrusiveHashMap(Entry, void, 50, struct {
        pub fn hash(_: @This(), entry: Entry) u64 {
            var hasher = std.hash.Wyhash.init(0);
            switch (entry.address) {
                .ipv4 => |ipv4| {
                    hasher.update(&ipv4.host.octets);
                    hasher.update(mem.asBytes(&ipv4.port));
                },
                .ipv6 => |ipv6| {
                    hasher.update(&ipv6.host.octets);
                    hasher.update(mem.asBytes(&ipv6.host.scope_id));
                    hasher.update(mem.asBytes(&ipv6.port));
                },
            }
            hasher.update(&entry.transaction_id);
            return hasher.final();
        }

        pub fn eql(_: @This(), a: Entry, b: Entry) bool {
            switch (a.address) {
                .ipv4 => {
                    if (b.address != .ipv4) return false;
                    if (a.address.ipv4.port != b.address.ipv4.port) return false;
                    if (!a.address.ipv4.host.eql(b.address.ipv4.host)) return false;
                },
                .ipv6 => {
                    if (b.address != .ipv6) return false;
                    if (a.address.ipv6.port != b.address.ipv6.port) return false;
                    if (!a.address.ipv6.host.eql(b.address.ipv6.host)) return false;
                },
            }
            return mem.eql(u8, &a.transaction_id, &b.transaction_id);
        }
    });

    const Entry = struct {
        address: ip.Address,
        transaction_id: [32]u8,
    };

    pub const max_num_bytes_per_batch = net.Packet.max_size - net.Packet.size;

    pub const flush_delay_min: i64 = 100 * time.ns_per_ms;
    pub const flush_delay_max: i64 = 500 * time.ns_per_ms;

    pub const connected_delay_min: i64 = 0 * time.ns_per_ms;
    pub const connected_delay_max: i64 = 500 * time.ns_per_ms;

    node: *Node,
    cache: Cache,

    last_flush_time: i64 = 0,
    flush_delay: i64 = flush_delay_min,
    connected_delay: i64 = connected_delay_min,

    wg: sync.WaitGroup = .{},
    pending: std.ArrayListUnmanaged(*Transaction) = .{},
    num_bytes_pending: usize = 0,

    pub fn init(gpa: *mem.Allocator, node: *Node) !TransactionPusher {
        var cache = try Cache.initCapacity(gpa, 1 << 16);
        errdefer cache.deinit(gpa);

        return TransactionPusher{ .node = node, .cache = cache };
    }

    pub fn deinit(self: *TransactionPusher, ctx: *Context, gpa: *mem.Allocator) void {
        log.info("shutting down...", .{});

        self.wg.wait(ctx) catch |err| log.warn("reported an error while shutting down: {}", .{err});

        self.cache.deinit(gpa);

        for (self.pending.items) |tx| {
            tx.deinit(gpa);
        }
        self.pending.deinit(gpa);

        log.info("successfully shut down", .{});
    }

    pub fn push(self: *TransactionPusher, ctx: *Context, gpa: *mem.Allocator, tx: *Transaction) !void {
        const tx_size = tx.size();
        if (self.num_bytes_pending + tx_size >= max_num_bytes_per_batch) {
            try self.flush(ctx, gpa);
        }

        try self.pending.append(gpa, tx);
        self.num_bytes_pending += tx_size;
    }

    pub fn run(self: *TransactionPusher, ctx: *Context, gpa: *mem.Allocator) !void {
        while (true) {
            if (self.num_bytes_pending == 0 or time.milliTimestamp() - self.last_flush_time < flush_delay_min / time.ns_per_ms) {
                try runtime.timeout(ctx, .{ .nanoseconds = self.flush_delay });
                self.flush_delay = math.min(flush_delay_max, self.flush_delay * 2);
                continue;
            }

            self.flush_delay = flush_delay_min;

            self.flush(ctx, gpa) catch |err| switch (err) {
                error.Cancelled => return err,
                else => log.warn("error while flushing: {}", .{err}),
            };
        }
    }

    pub fn flush(self: *TransactionPusher, ctx: *Context, gpa: *mem.Allocator) !void {
        while (self.node.clients.count() == 0) {
            try runtime.timeout(ctx, .{ .nanoseconds = self.connected_delay });
            self.connected_delay = math.min(connected_delay_max, self.connected_delay + (connected_delay_max - connected_delay_min) / 10);
        }

        self.connected_delay = connected_delay_min;

        const task = try gpa.create(@Frame(gossipTransactions));
        task.* = async self.gossipTransactions(ctx, gpa);
    }

    fn destroyGossipTransactionsFrame(self: *TransactionPusher, gpa: *mem.Allocator, frame: *@Frame(gossipTransactions)) void {
        gpa.destroy(frame);
        self.wg.sub(1);
    }

    fn gossipTransactions(self: *TransactionPusher, ctx: *Context, gpa: *mem.Allocator) !void {
        self.wg.add(1);
        defer {
            suspend {
                self.destroyGossipTransactionsFrame(gpa, @frame());
            }
        }

        const transactions = self.pending.toOwnedSlice(gpa);
        defer {
            for (transactions) |tx| {
                tx.deinit(gpa);
            }
            gpa.free(transactions);
        }

        self.num_bytes_pending = 0;

        const frames = try gpa.alloc(@Frame(pushTransactions), self.node.clients.count());
        defer gpa.free(frames);

        var frame_index: usize = 0;
        defer for (frames[0..frame_index]) |*frame| await frame catch {};

        var wg: sync.WaitGroup = .{};
        defer wg.wait(ctx) catch {};

        var it = self.node.clients.keyIterator();
        while (it.next()) |address_ptr| : (frame_index += 1) {
            var filtered_transactions: std.ArrayListUnmanaged(*Transaction) = .{};
            defer filtered_transactions.deinit(gpa);

            var filtered_transactions_len: u32 = 0;
            for (transactions) |tx| {
                const entry: Entry = .{
                    .address = address_ptr.*,
                    .transaction_id = tx.id,
                };

                if (self.cache.update(entry, {}) == .updated) {
                    continue;
                }

                try filtered_transactions.append(gpa, tx);
                filtered_transactions_len += tx.size();
            }

            frames[frame_index] = async self.pushTransactions(
                ctx,
                gpa,
                &wg,
                address_ptr.*,
                filtered_transactions.toOwnedSlice(gpa),
                filtered_transactions_len,
            );
        }
    }

    fn pushTransactions(
        self: *TransactionPusher,
        ctx: *Context,
        gpa: *mem.Allocator,
        wg: *sync.WaitGroup,
        address: ip.Address,
        transactions: []const *Transaction,
        transactions_len: u32,
    ) !void {
        wg.add(1);
        defer wg.sub(1);

        defer gpa.free(transactions);

        const writer = try self.node.acquireWriter(ctx, gpa, address);
        defer self.node.releaseWriter(address, writer);

        try (net.Packet{
            .len = transactions_len,
            .nonce = 0,
            .op = .command,
            .tag = .push_transaction,
        }).write(writer);

        var transaction_bytes: usize = 0;
        var transaction_index: usize = 0;
        defer {
            _ = pusher_bytes.fetchAdd(transaction_bytes, .Monotonic);
            _ = pusher_count.fetchAdd(transaction_index, .Monotonic);
        }

        while (transaction_index < transactions.len) {
            try transactions[transaction_index].write(writer);
            transaction_bytes += transactions[transaction_index].size();
            transaction_index += 1;
        }
    }
};

pub const TransactionVerifier = struct {
    const log = std.log.scoped(.tx_verifier);

    pub const max_signature_batch_size = 64;
    pub const max_num_allowed_parallel_tasks = 256;

    pub const flush_delay_min: i64 = 100 * time.ns_per_ms;
    pub const flush_delay_max: i64 = 500 * time.ns_per_ms;

    pub const Task = extern struct {
        next: ?*TransactionVerifier.Task = null,
    };

    node: *Node,

    pool_wg: sync.WaitGroup = .{},
    pool_parker: sync.Parker(void) = .{},
    pool: SinglyLinkedList(TransactionVerifier.Task, .next) = .{},

    entries: std.ArrayListUnmanaged(*Transaction) = .{},
    last_flush_time: i64 = 0,

    pub fn init(node: *Node) TransactionVerifier {
        return TransactionVerifier{ .node = node };
    }

    pub fn deinit(self: *TransactionVerifier, ctx: *Context, gpa: *mem.Allocator) void {
        log.info("shutting down...", .{});

        self.pool_wg.wait(ctx) catch |err| log.warn("error while shutting down: {}", .{err});

        for (self.entries.items) |tx| {
            tx.deinit(gpa);
        }
        self.entries.deinit(gpa);

        while (self.pool.popFirst()) |task| {
            gpa.free(@ptrCast([*]u8, task)[0 .. @sizeOf(TransactionVerifier.Task) + @frameSize(TransactionVerifier.runTask)]);
        }

        log.info("successfully shut down", .{});
    }

    pub fn push(self: *TransactionVerifier, ctx: *Context, gpa: *mem.Allocator, tx: *Transaction) !void {
        while (self.pool_wg.len == max_num_allowed_parallel_tasks) {
            try self.pool_parker.park(ctx);
        }

        try self.entries.append(gpa, tx);

        if (self.entries.items.len == max_signature_batch_size) {
            try self.flush(ctx, gpa);
        }
    }

    pub fn run(self: *TransactionVerifier, ctx: *Context, gpa: *mem.Allocator) !void {
        var flush_delay: i64 = flush_delay_min;

        while (true) {
            while (self.pool_wg.len == max_num_allowed_parallel_tasks) {
                try self.pool_parker.park(ctx);
            }

            if (self.entries.items.len == 0 or time.milliTimestamp() - self.last_flush_time < flush_delay_min / time.ns_per_ms) {
                try runtime.timeout(ctx, .{ .nanoseconds = flush_delay });
                flush_delay = math.min(flush_delay_max, flush_delay * 2);
                continue;
            }

            flush_delay = flush_delay_min;

            self.flush(ctx, gpa) catch |err| log.warn("error while flushing: {}", .{err});
        }
    }

    fn flush(self: *TransactionVerifier, ctx: *Context, gpa: *mem.Allocator) !void {
        const task = task: {
            if (self.pool.popFirst()) |task| {
                break :task task;
            }
            const task_align = @alignOf(@Frame(TransactionVerifier.runTask));
            const task_length = @sizeOf(TransactionVerifier.Task) + @frameSize(TransactionVerifier.runTask);
            const task_bytes = try gpa.alignedAlloc(u8, task_align, task_length);
            break :task @ptrCast(*TransactionVerifier.Task, task_bytes);
        };

        const task_frame = @ptrCast(*@Frame(TransactionVerifier.runTask), @ptrCast([*]u8, task) + @sizeOf(TransactionVerifier.Task));

        task.* = .{};
        task_frame.* = async self.runTask(ctx, task, gpa, self.entries.toOwnedSlice(gpa));

        self.last_flush_time = time.milliTimestamp();
    }

    fn runTask(self: *TransactionVerifier, ctx: *Context, task: *TransactionVerifier.Task, gpa: *mem.Allocator, entries: []*Transaction) void {
        self.pool_wg.add(1);
        defer self.pool_wg.sub(1);

        defer {
            self.pool.prepend(task);
            self.pool_parker.notify({});
        }

        var index: usize = 0;

        {
            runtime.startCpuBoundOperation();
            defer runtime.endCpuBoundOperation();

            var num: usize = 0;
            while (entries.len - num >= max_signature_batch_size) : (num += max_signature_batch_size) {
                crypto.verifyBatch(entries[num..][0..max_signature_batch_size]) catch |batch_err| {
                    log.warn("bad transaction batch: {}", .{batch_err});

                    for (entries[num..][0..max_signature_batch_size]) |tx| {
                        crypto.verify(tx.signature, tx, tx.sender) catch |err| {
                            log.warn("bad transaction {}: {}", .{ fmt.fmtSliceHexLower(&tx.id), err });
                            tx.deinit(gpa);
                            continue;
                        };

                        entries[index] = tx;
                        index += 1;
                    }

                    continue;
                };

                mem.copy(*Transaction, entries[index..], entries[num..][0..max_signature_batch_size]);
                index += max_signature_batch_size;
            }

            for (entries[num..]) |tx| {
                crypto.verify(tx.signature, tx, tx.sender) catch |err| {
                    log.warn("bad transaction {}: {}", .{ fmt.fmtSliceHexLower(&tx.id), err });
                    tx.deinit(gpa);
                    continue;
                };

                entries[index] = tx;
                index += 1;
            }
        }

        defer gpa.free(entries);

        self.node.chain.pending.ensureUnusedCapacity(gpa, index) catch {
            for (entries[0..index]) |tx| {
                tx.deinit(gpa);
            }
            return;
        };

        for (entries[0..index]) |tx| {
            self.node.addTransaction(ctx, gpa, tx) catch {
                tx.deinit(gpa);
                continue;
            };
        }
    }
};

pub const Sampler = struct {
    pub const default_alpha = 0.80;
    pub const default_beta = 150;

    pub const Vote = struct {
        block: ?*Block,
        tally: f64,
    };

    counts: HashMap(usize, 50),
    count: usize = 0,
    stalled: usize = 0,
    preferred: ?*Block = null,
    last: ?*Block = null,

    pub fn init(gpa: *mem.Allocator) !Sampler {
        var counts = try HashMap(usize, 50).init(gpa);
        errdefer counts.deinit(gpa);

        return Sampler{ .counts = counts };
    }

    pub fn deinit(self: *Sampler, gpa: *mem.Allocator) void {
        self.counts.deinit(gpa);
        if (self.preferred) |preferred| {
            preferred.deinit(gpa);
        }
        if (self.last) |last| {
            last.deinit(gpa);
        }
    }

    pub fn reset(self: *Sampler, gpa: *mem.Allocator) void {
        self.counts.clearRetainingCapacity();
        self.count = 0;
        self.stalled = 0;

        if (self.preferred) |preferred| {
            preferred.deinit(gpa);
        }
        self.preferred = null;

        if (self.last) |last| {
            last.deinit(gpa);
        }
        self.last = null;
    }

    pub fn prefer(self: *Sampler, gpa: *mem.Allocator, block: *Block) void {
        if (self.preferred) |preferred| {
            preferred.deinit(gpa);
        }
        self.preferred = block;
    }

    pub fn update(self: *Sampler, gpa: *mem.Allocator, votes: []const Vote) !?*Block {
        try self.counts.ensureUnusedCapacity(gpa, 1);

        if (votes.len == 0) return null;

        var majority_vote = votes[0];
        for (votes[1..]) |vote| {
            if (vote.block == null) continue;
            if (majority_vote.tally >= vote.tally) continue;
            majority_vote = vote;
        }

        const majority_block = majority_vote.block orelse {
            self.count = 0;
            return null;
        };

        if (majority_vote.tally < default_alpha) {
            self.stalled += 1;
            if (self.stalled >= default_beta) {
                if (self.preferred) |preferred| {
                    preferred.deinit(gpa);
                }
                self.preferred = null;
                self.stalled = 0;
            }
            self.count = 0;
            return null;
        }

        // TODO: getEntry() can be added to allow for emplacement of value

        const count = (self.counts.get(majority_block.id) orelse 0) + 1;
        self.counts.putAssumeCapacity(majority_block.id, count);

        if (self.preferred) |preferred| {
            if (count > self.counts.get(preferred.id).?) {
                self.preferred = majority_block.ref();
                preferred.deinit(gpa);
            }
        } else {
            self.preferred = majority_block.ref();
        }

        if (self.last) |last| {
            if (!mem.eql(u8, &last.id, &majority_block.id)) {
                self.last = majority_block.ref();
                self.count = 1;
                last.deinit(gpa);
                return null;
            }
        } else {
            self.last = majority_block.ref();
            self.count = 1;
            return null;
        }

        self.count += 1;
        if (self.count > default_beta) {
            return self.preferred;
        }

        return null;
    }
};

/// 'head' and 'tail' are set at 1 until genesis blocks are implemented. Genesis
/// blocks are blocks whose height is 0. Until they are implemented it is safe to
/// assume that the first block that is to be pushed into this ring buffer starts
/// at height 1.
pub const BlockRingBuffer = struct {
    pub const capacity = 32;

    comptime {
        assert(math.isPowerOfTwo(capacity));
    }

    const Self = @This();

    head: u64 = 1,
    tail: u64 = 1,
    entries: [capacity]*Block = undefined,

    /// This routine pushes a block, and optionally returns an evicted block should
    /// the insertion of the provided block overflow the existing buffer.
    ///
    /// The block that is pushed in is assumed to have a height that is one larger
    /// than the most recently buffered block.
    pub fn push(self: *Self, item: *Block) ?*Block {
        assert(item.height == self.head);

        const evicted = evicted: {
            if (self.count() == capacity) {
                const evicted = self.entries[self.tail & (capacity - 1)];
                self.tail +%= 1;
                break :evicted evicted;
            }
            break :evicted null;
        };

        self.entries[self.head & (capacity - 1)] = item;
        self.head +%= 1;

        return evicted;
    }

    /// This routine pops a block from the tail of the buffer and returns it provided
    /// that the buffer is not empty.
    ///
    /// This routine is typically used in order to pop and de-initialize all blocks
    /// stored in the buffer.
    pub fn pop(self: *Self) ?*Block {
        if (self.count() == 0) return null;
        const evicted = self.entries[self.tail & (capacity - 1)];
        self.tail +%= 1;
        return evicted;
    }

    pub fn get(self: Self, height: u64) ?*Block {
        if (height < self.tail or height >= self.head) return null;
        return self.entries[height & (capacity - 1)];
    }

    pub fn count(self: Self) usize {
        return self.head -% self.tail;
    }

    pub fn latest(self: Self) ?*Block {
        if (self.count() == 0) return null;
        return self.entries[(self.head - 1) & (capacity - 1)];
    }

    pub fn oldest(self: *Self) ?*Block {
        if (self.count() == 0) return null;
        return self.entries[(self.tail - 1) & (capacity - 1)];
    }
};
