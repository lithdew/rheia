const std = @import("std");
const net = @import("net.zig");
const lru = @import("lru.zig");
const http = @import("http.zig");
const args = @import("args.zig");
const sync = @import("sync.zig");
const crypto = @import("crypto.zig");
const runtime = @import("runtime.zig");
const kademlia = @import("kademlia.zig");

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
const AutoHashMap = @import("hash_map.zig").AutoHashMap;
const SortedHashMap = @import("hash_map.zig").SortedHashMap;
const StaticRingBuffer = @import("ring_buffer.zig").StaticRingBuffer;

const assert = std.debug.assert;

pub const log_level = .debug;

const usage = fmt.comptimePrint(
    \\rheia
    \\
    \\Usage:
    \\  rheia [options] [--] ([<host>][:]<port>)...
    \\  rheia -h | --help
    \\  rheia --version
    \\
    \\Arguments:
    \\  ([<host>][:]<port>...)                    List of peer addresses to bootstrap with.
    \\
    \\Options:
    \\  -h, --help                                Show this screen.
    \\  -v, --version                             Show version.
    \\  -d, --database-path                       File path for storing all state and data. (env: DB_PATH)
    \\  -l, --listen-address ([<host>][:]<port>)  Address to listen for peers on. (env: LISTEN_ADDR) [default: 0.0.0.0:9000]
    \\  -b, --http-address ([<host>][:]<port>)    Address to handle HTTP requests on. (env: HTTP_ADDR) [default: 0.0.0.0:8080]
    \\  -n, --node-address ([<host>][:]<port>)    Address for peers to reach this node on. (env: NODE_ADDR) [default: --listen-address]
    \\  -s, --secret-key <secret key>             Hex-encoded Ed25519 secret key of this node. (env: SECRET_KEY) [default: randomly generated]
    \\
    \\To spawn and bootstrap a three-node Rheia cluster:
    \\  rheia -l 9000
    \\  rheia -l 9001 127.0.0.1:9000
    \\  rheia -l 9002 127.0.0.1:9000
, .{});

pub const EnvironmentVariables = struct {
    listen_address: ?[]const u8 = null,
    http_address: ?[]const u8 = null,
    node_address: ?[]const u8 = null,
    database_path: ?[]const u8 = null,
    secret_key: ?[]const u8 = null,

    pub fn parse() EnvironmentVariables {
        return EnvironmentVariables{
            .listen_address = os.getenv("LISTEN_ADDR"),
            .http_address = os.getenv("HTTP_ADDR"),
            .node_address = os.getenv("NODE_ADDR"),
            .database_path = os.getenv("DB_PATH"),
            .secret_key = os.getenv("SECRET_KEY"),
        };
    }
};

pub const Arguments = struct {
    @"listen-address": ?[]const u8 = null,
    @"http-address": ?[]const u8 = null,
    @"node-address": ?[]const u8 = null,
    @"database-path": ?[]const u8 = null,
    @"secret-key": ?[]const u8 = null,
    help: bool = false,
    version: bool = false,

    pub const shorthands = .{
        .h = "help",
        .v = "version",
        .d = "database-path",
        .l = "listen-address",
        .b = "http-address",
        .n = "node-address",
        .s = "secret-key",
    };

    pub fn parse(gpa: mem.Allocator) !args.ParseArgsResult(Arguments) {
        return args.parseForCurrentProcess(Arguments, gpa, .print);
    }
};

pub const Options = struct {
    listen_address: ip.Address,
    http_address: ip.Address,
    node_address: ip.Address,
    database_path: ?[]const u8,
    bootstrap_addresses: []const ip.Address,
    keys: Ed25519.KeyPair,

    pub fn parse(gpa: mem.Allocator) !Options {
        errdefer {
            if (@errorReturnTrace()) |stack_trace| {
                std.debug.dumpStackTrace(stack_trace.*);
            }
            os.exit(0);
        }

        // parse environment variables

        const env = EnvironmentVariables.parse();

        // parse command-line arguments

        const arguments = try Arguments.parse(gpa);
        defer arguments.deinit();

        if (arguments.options.help) {
            std.debug.print("{s}\n", .{usage});
            return error.Cancelled;
        }

        if (arguments.options.version) {
            std.debug.print("rheia v0.0.1", .{});
            return error.Cancelled;
        }

        var maybe_listen_address: ?ip.Address = null;
        var maybe_http_address: ?ip.Address = null;
        var maybe_node_address: ?ip.Address = null;

        var maybe_database_path: ?[]const u8 = null;
        errdefer if (maybe_database_path) |text| gpa.free(text);

        var maybe_keys: ?Ed25519.KeyPair = null;

        // take from environment variables first

        if (env.listen_address) |text| maybe_listen_address = try net.parseIpAddress(text);
        if (env.http_address) |text| maybe_http_address = try net.parseIpAddress(text);
        if (env.node_address) |text| maybe_node_address = try net.parseIpAddress(text);

        if (env.database_path) |text| {
            if (maybe_database_path) |old_text| {
                gpa.free(old_text);
                maybe_database_path = null;
            }
            maybe_database_path = text;
        }

        if (env.secret_key) |text| {
            var buf: [32]u8 = undefined;
            maybe_keys = try Ed25519.KeyPair.create((try fmt.hexToBytes(&buf, text))[0..32].*);
        }

        // take from command-line arguments second

        if (arguments.options.@"listen-address") |text| maybe_listen_address = try net.parseIpAddress(text);
        if (arguments.options.@"http-address") |text| maybe_http_address = try net.parseIpAddress(text);
        if (arguments.options.@"node-address") |text| maybe_node_address = try net.parseIpAddress(text);

        if (arguments.options.@"database-path") |text| {
            if (maybe_database_path) |old_text| {
                gpa.free(old_text);
                maybe_database_path = null;
            }
            maybe_database_path = try gpa.dupe(u8, text);
        }

        if (arguments.options.@"secret-key") |text| {
            var buf: [32]u8 = undefined;
            maybe_keys = try Ed25519.KeyPair.create((try fmt.hexToBytes(&buf, text))[0..32].*);
        }

        // load bootstrap addresses from command-line positional arguments

        const bootstrap_addresses = try gpa.alloc(ip.Address, arguments.positionals.len);
        errdefer gpa.free(bootstrap_addresses);

        for (arguments.positionals) |arg, i| {
            bootstrap_addresses[i] = try net.parseIpAddress(arg);
        }

        // load default values

        const listen_address = maybe_listen_address orelse ip.Address.initIPv4(IPv4.unspecified, 9000);
        const http_address = maybe_http_address orelse ip.Address.initIPv4(IPv4.unspecified, 8080);
        const node_address = maybe_node_address orelse listen_address;

        const database_path = maybe_database_path;
        const keys = maybe_keys orelse try Ed25519.KeyPair.create(null);

        return Options{
            .listen_address = listen_address,
            .http_address = http_address,
            .node_address = node_address,
            .database_path = database_path,
            .keys = keys,
            .bootstrap_addresses = bootstrap_addresses,
        };
    }

    pub fn deinit(self: Options, gpa: mem.Allocator) void {
        if (self.database_path) |text| {
            gpa.free(text);
        }
        gpa.free(self.bootstrap_addresses);
    }
};

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

    const options = try Options.parse(runtime.getAllocator());
    defer options.deinit(runtime.getAllocator());

    log.debug("advertising to peers our address is: {}", .{options.node_address});
    log.debug("public key: {}", .{fmt.fmtSliceHexLower(options.keys.public_key[0..Ed25519.public_length])});
    log.debug("secret key: {}", .{fmt.fmtSliceHexLower(options.keys.secret_key[0..Ed25519.seed_length])});

    log.info("press ctrl+c to commence graceful shutdown", .{});

    var ctx: Context = .{};
    defer ctx.cancel();

    var store = try SqliteStore.init(runtime.getAllocator(), options.database_path);
    defer store.deinit();

    // var store = try NullStore.init(runtime.getAllocator(), options.database_path);
    // defer store.deinit();

    var node: Node = undefined;
    try node.init(runtime.getAllocator(), &store, options.keys, options.node_address);
    defer {
        var shutdown_ctx: Context = .{};
        defer shutdown_ctx.cancel();

        node.deinit(&shutdown_ctx, runtime.getAllocator());
    }

    var node_frame = async node.run(&ctx, runtime.getAllocator());
    defer await node_frame catch |err| log.warn("node error: {}", .{err});

    var node_listener_frame = async startNodeListener(&ctx, options, &node);
    defer await node_listener_frame catch |err| log.warn("node listener error: {}", .{err});

    var http_listener_frame = async startHttpListener(&ctx, options, &node);
    defer await http_listener_frame catch |err| log.warn("http listener error: {}", .{err});

    var stats_frame = async reportStatistics(&ctx);
    defer await stats_frame catch |err| log.warn("stats error: {}", .{err});

    for (options.bootstrap_addresses) |bootstrap_address| {
        const client = node.getOrCreateClient(&ctx, runtime.getAllocator(), bootstrap_address) catch |err| {
            log.warn("failed to bootstrap with {}: {}", .{ bootstrap_address, err });
            continue;
        };
        try client.ensureConnectionAvailable(&ctx, runtime.getAllocator());
    }

    try bootstrapNodeWithPeers(&ctx, &node);

    runtime.waitForSignal(&ctx, .{os.SIG.INT}) catch {};
    log.info("gracefully shutting down...", .{});

    ctx.cancel();
}

pub fn startNodeListener(ctx: *Context, options: Options, node: *Node) !void {
    const log = std.log.scoped(.main);
    defer ctx.cancel();

    var tcp_listener = try tcp.Listener.init(.ip, .{ .close_on_exec = true });
    defer tcp_listener.deinit();

    try tcp_listener.setReuseAddress(true);
    try tcp_listener.setReusePort(true);
    try tcp_listener.setFastOpen(true);

    try tcp_listener.bind(options.listen_address);
    try tcp_listener.listen(128);

    var listener: Listener = .{ .node = node };
    var net_listener = net.Listener(Listener).init(&listener);
    defer {
        var shutdown_ctx: Context = .{};
        defer shutdown_ctx.cancel();

        if (net_listener.deinit(&shutdown_ctx)) |_| {
            log.info("node listener successfully shut down", .{});
        } else |err| {
            log.warn("node listener reported an error while shutting down: {}", .{err});
        }
    }

    return Listener.serve(ctx, runtime.getAllocator(), &net_listener, tcp_listener);
}

pub fn startHttpListener(ctx: *Context, options: Options, node: *Node) !void {
    const log = std.log.scoped(.main);
    defer ctx.cancel();

    var tcp_listener = try tcp.Listener.init(.ip, .{ .close_on_exec = true });
    defer tcp_listener.deinit();

    try tcp_listener.setReuseAddress(true);
    try tcp_listener.setReusePort(true);
    try tcp_listener.setFastOpen(true);

    try tcp_listener.bind(options.http_address);
    try tcp_listener.listen(128);

    var http_handler: HttpHandler = .{ .node = node };
    var http_listener = http.Listener(HttpHandler).init(&http_handler);
    var net_listener = net.Listener(http.Listener(HttpHandler)).init(&http_listener);
    defer {
        var shutdown_ctx: Context = .{};
        defer shutdown_ctx.cancel();

        if (net_listener.deinit(&shutdown_ctx)) |_| {
            log.info("http listener successfully shut down", .{});
        } else |err| {
            log.warn("http listener reported an error while shutting down: {}", .{err});
        }
    }

    return http.Listener(HttpHandler).serve(ctx, runtime.getAllocator(), &net_listener, tcp_listener);
}

fn bootstrapNodeWithPeers(ctx: *Context, node: *Node) !void {
    const log = std.log.scoped(.main);

    var finder = try kademlia.NodeFinder.init(runtime.getAllocator(), node);
    defer finder.deinit(ctx, runtime.getAllocator());

    var peer_ids: [16]kademlia.ID = undefined;
    const num_peer_ids = try finder.find(ctx, runtime.getAllocator(), &peer_ids, node.keys.public_key);

    for (peer_ids[0..num_peer_ids]) |id| {
        log.info("got peer id: {}", .{id});
    }

    log.info("total peers connected to: {}", .{node.table.len});
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

pub const Block = struct {
    pub const header_size = @sizeOf(u64) + @sizeOf([32]u8) + @sizeOf(u16);
    pub const max_num_transaction_ids: u16 = (net.Packet.max_size - net.Packet.size - Block.header_size) / @sizeOf([32]u8) / 2;

    pub const Summary = struct {
        id: [32]u8,
        height: u64,
        merkle_root: [32]u8,
        num_transaction_ids: u16,

        pub fn jsonStringify(self: Block.Summary, options: std.json.StringifyOptions, writer: anytype) !void {
            _ = options;

            var stream = std.json.writeStream(writer, 4);
            var buf: [64]u8 = undefined;

            try stream.beginObject();

            try stream.objectField("id");
            try stream.emitString(fmt.bufPrint(&buf, "{}", .{fmt.fmtSliceHexLower(&self.id)}) catch unreachable);

            try stream.objectField("height");
            try stream.emitNumber(self.height);

            try stream.objectField("merkle_root");
            try stream.emitString(fmt.bufPrint(&buf, "{}", .{fmt.fmtSliceHexLower(&self.merkle_root)}) catch unreachable);

            try stream.objectField("num_transaction_ids");
            try stream.emitNumber(self.num_transaction_ids);
            try stream.endObject();
        }
    };

    pub const Data = struct {
        id: [32]u8,
        height: u64,
        merkle_root: [32]u8,
        transaction_ids: []const [32]u8,
    };

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

    pub fn create(gpa: mem.Allocator, params: Block.Params) !*Block {
        const bytes_len = @sizeOf(Block) + params.transaction_ids.len * @sizeOf([32]u8);
        const bytes = try gpa.alignedAlloc(u8, math.max(@alignOf(Block), @alignOf([32]u8)), bytes_len);
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

    pub fn from(gpa: mem.Allocator, format: Block.Data) !*Block {
        const bytes_len = @sizeOf(Block) + format.transaction_ids.len * @sizeOf([32]u8);
        const bytes = try gpa.alignedAlloc(u8, math.max(@alignOf(Block), @alignOf([32]u8)), bytes_len);
        errdefer gpa.free(bytes);

        const block = @ptrCast(*Block, bytes.ptr);

        block.refs = 1;
        block.height = format.height;
        block.merkle_root = format.merkle_root;
        block.num_transaction_ids = @intCast(u16, format.transaction_ids.len);

        block.transaction_ids = @ptrCast([*][32]u8, bytes.ptr + @sizeOf(Block));
        mem.copy([32]u8, block.transaction_ids[0..block.num_transaction_ids], format.transaction_ids);

        block.id = format.id;

        return block;
    }

    pub fn deinit(self: *Block, gpa: mem.Allocator) void {
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

    pub fn read(gpa: mem.Allocator, reader: anytype) !*Block {
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

    pub fn jsonStringify(self: Block, options: std.json.StringifyOptions, writer: anytype) !void {
        _ = options;

        var stream = std.json.writeStream(writer, 4);
        var buf: [64]u8 = undefined;

        try stream.beginObject();

        try stream.objectField("id");
        try stream.emitString(fmt.bufPrint(&buf, "{}", .{fmt.fmtSliceHexLower(&self.id)}) catch unreachable);

        try stream.objectField("height");
        try stream.emitNumber(self.height);

        try stream.objectField("merkle_root");
        try stream.emitString(fmt.bufPrint(&buf, "{}", .{fmt.fmtSliceHexLower(&self.merkle_root)}) catch unreachable);

        try stream.objectField("transaction_ids");
        try stream.beginArray();
        for (self.transaction_ids[0..self.num_transaction_ids]) |transaction_id| {
            try stream.arrayElem();
            try stream.emitString(fmt.bufPrint(&buf, "{}", .{fmt.fmtSliceHexLower(&transaction_id)}) catch unreachable);
        }
        try stream.endArray();

        try stream.endObject();
    }
};

pub const Transaction = struct {
    pub const header_size = @sizeOf([32]u8) + @sizeOf([64]u8) + @sizeOf(u32) + @sizeOf(u64) + @sizeOf(u64) + @sizeOf(Transaction.Tag);

    pub const Tag = enum(u8) {
        pub const BaseType = []const u8;

        no_op,
        stmt,
    };

    pub const Data = struct {
        id: [32]u8,
        sender: [32]u8,
        signature: [64]u8,
        sender_nonce: u64,
        created_at: u64,
        tag: Tag,
        data: []const u8,
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

    pub fn create(gpa: mem.Allocator, keys: Ed25519.KeyPair, params: Transaction.Params) !*Transaction {
        const bytes = try gpa.alignedAlloc(u8, math.max(@alignOf(Transaction), @alignOf(u8)), @sizeOf(Transaction) + params.data.len);
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

    pub fn from(gpa: mem.Allocator, format: Transaction.Data) !*Transaction {
        const bytes = try gpa.alignedAlloc(u8, math.max(@alignOf(Transaction), @alignOf(u8)), @sizeOf(Transaction) + format.data.len);
        errdefer gpa.free(bytes);

        const tx = @ptrCast(*Transaction, bytes.ptr);

        tx.refs = 1;
        tx.sender = format.sender;
        tx.data_len = @intCast(u32, format.data.len);

        tx.sender_nonce = format.sender_nonce;
        tx.created_at = format.created_at;
        tx.tag = format.tag;

        tx.data = bytes.ptr + @sizeOf(Transaction);
        mem.copy(u8, tx.data[0..tx.data_len], format.data);

        tx.signature = format.signature;
        tx.id = format.id;

        return tx;
    }

    pub fn deinit(self: *Transaction, gpa: mem.Allocator) void {
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

    pub fn read(gpa: mem.Allocator, reader: anytype) !*Transaction {
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

    pub fn jsonStringify(self: Transaction, options: std.json.StringifyOptions, writer: anytype) !void {
        _ = options;

        var stream = std.json.writeStream(writer, 4);
        var buf: [128]u8 = undefined;

        try stream.beginObject();

        try stream.objectField("id");
        try stream.emitString(fmt.bufPrint(&buf, "{}", .{fmt.fmtSliceHexLower(&self.id)}) catch unreachable);

        try stream.objectField("sender");
        try stream.emitString(fmt.bufPrint(&buf, "{}", .{fmt.fmtSliceHexLower(&self.sender)}) catch unreachable);

        try stream.objectField("signature");
        try stream.emitString(fmt.bufPrint(&buf, "{}", .{fmt.fmtSliceHexLower(&self.signature)}) catch unreachable);

        try stream.objectField("sender_nonce");
        try stream.emitNumber(self.sender_nonce);

        try stream.objectField("created_at");
        try stream.emitNumber(self.created_at);

        try stream.objectField("tag");
        try stream.emitString(@tagName(self.tag));

        try stream.objectField("data");
        try stream.emitString(self.data[0..self.data_len]);

        try stream.endObject();
    }
};

test "Block: create, serialize, and deserialize" {
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

test "Transaction: create, serialize, and deserialize" {
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

pub const Client = struct {
    const log = std.log.scoped(.node_client);

    base: net.Client(Client),
    rpc: net.RPC,

    pub fn init(gpa: mem.Allocator, address: ip.Address) !Client {
        var rpc = try net.RPC.init(gpa, 65536);
        errdefer rpc.deinit(gpa);

        return Client{ .base = try net.Client(Client).init(gpa, address), .rpc = rpc };
    }

    pub fn deinit(self: *Client, ctx: *Context, gpa: mem.Allocator) !void {
        const result = self.base.deinit(ctx);
        self.rpc.deinit(gpa);
        return result;
    }

    pub fn acquireWriter(self: *Client, ctx: *Context, gpa: mem.Allocator) !std.ArrayList(u8).Writer {
        return self.base.acquireWriter(ctx, gpa);
    }

    pub fn releaseWriter(self: *Client, writer: std.ArrayList(u8).Writer) void {
        return self.base.releaseWriter(writer);
    }

    pub fn ensureConnectionAvailable(self: *Client, ctx: *Context, gpa: mem.Allocator) !void {
        return self.base.ensureConnectionAvailable(ctx, gpa);
    }

    pub fn runWriteLoop(self: *Client, ctx: *Context, gpa: mem.Allocator, client: tcp.Client) !void {
        var stream: runtime.Stream = .{ .socket = client.socket, .context = ctx };
        var writer = stream.writer();

        while (true) {
            while (self.base.buffer.items.len == 0) {
                try self.base.writer_parker.park(ctx);
            }

            const buffer = self.base.buffer.toOwnedSlice();
            defer gpa.free(buffer);

            try writer.writeAll(buffer);
            self.base.write_parker.notify({});
        }
    }

    pub fn runReadLoop(self: *Client, ctx: *Context, gpa: mem.Allocator, conn_id: usize, client: tcp.Client) !void {
        var stream: runtime.Stream = .{ .socket = client.socket, .context = ctx };
        var reader = stream.reader();

        var buffer = std.fifo.LinearFifo(u8, .Dynamic).init(gpa);
        defer buffer.deinit();

        while (true) {
            while (buffer.count < net.Packet.size) {
                const num_bytes = try reader.read(try buffer.writableWithSize(65536));
                if (num_bytes == 0) return;
                buffer.update(num_bytes);
            }

            const packet = try net.Packet.read(buffer.reader());

            while (buffer.count < packet.len) {
                const num_bytes = try reader.read(try buffer.writableWithSize(65536));
                if (num_bytes == 0) return;
                buffer.update(num_bytes);
            }

            const frame = try gpa.alloc(u8, packet.len);
            errdefer gpa.free(frame);

            try buffer.reader().readNoEof(frame);

            if (packet.op == .response) {
                if (!self.rpc.push(.{ .header = packet, .body = frame })) {
                    log.warn("{} [{}]: got an unexpected response (tag: {}, nonce: {})", .{
                        self.base.address,
                        conn_id,
                        packet.tag,
                        packet.nonce,
                    });
                    gpa.free(frame);
                }
                continue;
            }

            gpa.free(frame);
        }
    }

    pub fn sayHello(
        self: *Client,
        ctx: *Context,
        gpa: mem.Allocator,
        keys: Ed25519.KeyPair,
        id: kademlia.ID,
        timeout_params: runtime.TimeoutParams,
    ) !kademlia.ID {
        var rpc_ctx: Context = .{};
        defer rpc_ctx.cancel();

        var callback: struct {
            state: Context.Callback = .{ .run = @This().run },
            rpc_ctx: *Context,

            pub fn run(state: *Context.Callback) void {
                const callback = @fieldParentPtr(@This(), "state", state);
                callback.rpc_ctx.cancel();
            }
        } = .{ .rpc_ctx = &rpc_ctx };

        try ctx.register(&callback.state);
        defer ctx.deregister(&callback.state);

        var timeout: Context.Timeout = undefined;
        timeout.init(&rpc_ctx, timeout_params);
        defer timeout.deinit();

        try rpc_ctx.register(&timeout.state);
        defer rpc_ctx.deregister(&timeout.state);

        var entry: net.RPC.Entry = .{};
        var nonce = try self.rpc.register(&rpc_ctx, &entry);

        var rpc_callback = net.RPC.CancellationCallback.from(&self.rpc, nonce);
        try rpc_ctx.register(&rpc_callback.state);
        defer rpc_ctx.deregister(&rpc_callback.state);

        {
            const writer = try self.acquireWriter(&rpc_ctx, gpa);
            defer self.releaseWriter(writer);

            try (net.Packet{
                .len = id.size() + @sizeOf([64]u8),
                .nonce = nonce,
                .op = .request,
                .tag = .hello,
            }).write(writer);

            try id.write(writer);

            const signature = try crypto.sign(id, keys);
            try writer.writeAll(&signature);
        }

        const response = try await entry.response;
        defer response.deinit(gpa);

        var body = io.fixedBufferStream(response.body);

        return try kademlia.ID.read(body.reader());
    }

    pub fn pullBlock(
        self: *Client,
        ctx: *Context,
        gpa: mem.Allocator,
        block_height: u64,
        cached_block_proposal_id: ?[32]u8,
        timeout_params: runtime.TimeoutParams,
    ) !*Block {
        var rpc_ctx: Context = .{};
        defer rpc_ctx.cancel();

        var callback: struct {
            state: Context.Callback = .{ .run = @This().run },
            rpc_ctx: *Context,

            pub fn run(state: *Context.Callback) void {
                const callback = @fieldParentPtr(@This(), "state", state);
                callback.rpc_ctx.cancel();
            }
        } = .{ .rpc_ctx = &rpc_ctx };

        try ctx.register(&callback.state);
        defer ctx.deregister(&callback.state);

        var timeout: Context.Timeout = undefined;
        timeout.init(&rpc_ctx, timeout_params);
        defer timeout.deinit();

        try rpc_ctx.register(&timeout.state);
        defer rpc_ctx.deregister(&timeout.state);

        var entry: net.RPC.Entry = .{};
        var nonce = try self.rpc.register(&rpc_ctx, &entry);

        var rpc_callback = net.RPC.CancellationCallback.from(&self.rpc, nonce);
        try rpc_ctx.register(&rpc_callback.state);
        defer rpc_ctx.deregister(&rpc_callback.state);

        {
            const writer = try self.acquireWriter(&rpc_ctx, gpa);
            defer self.releaseWriter(writer);

            try (net.Packet{
                .len = @sizeOf(u64) + @as(u32, if (cached_block_proposal_id != null) @sizeOf([32]u8) else 0),
                .nonce = nonce,
                .op = .request,
                .tag = .pull_block,
            }).write(writer);

            try writer.writeIntLittle(u64, block_height);
            if (cached_block_proposal_id) |block_proposal_id| {
                try writer.writeAll(&block_proposal_id);
            }
        }

        const response = try await entry.response;
        defer response.deinit(gpa);

        var body = io.fixedBufferStream(response.body);

        const exists = (try body.reader().readByte()) != 0;
        if (!exists) return error.BlockNotExists;

        return Block.read(gpa, body.reader()) catch |err| {
            if (response.body.len == 1) {
                return error.BlockPulledIsCached;
            }
            return err;
        };
    }

    pub fn pullTransactions(
        self: *Client,
        ctx: *Context,
        gpa: mem.Allocator,
        ids: []const [32]u8,
        timeout_params: runtime.TimeoutParams,
    ) ![]*Transaction {
        var rpc_ctx: Context = .{};
        defer rpc_ctx.cancel();

        var callback: struct {
            state: Context.Callback = .{ .run = @This().run },
            rpc_ctx: *Context,

            pub fn run(state: *Context.Callback) void {
                const callback = @fieldParentPtr(@This(), "state", state);
                callback.rpc_ctx.cancel();
            }
        } = .{ .rpc_ctx = &rpc_ctx };

        try ctx.register(&callback.state);
        defer ctx.deregister(&callback.state);

        var timeout: Context.Timeout = undefined;
        timeout.init(&rpc_ctx, timeout_params);
        defer timeout.deinit();

        try rpc_ctx.register(&timeout.state);
        defer rpc_ctx.deregister(&timeout.state);

        var entry: net.RPC.Entry = .{};
        var nonce = try self.rpc.register(&rpc_ctx, &entry);

        var rpc_callback = net.RPC.CancellationCallback.from(&self.rpc, nonce);
        try rpc_ctx.register(&rpc_callback.state);
        defer rpc_ctx.deregister(&rpc_callback.state);

        {
            const writer = try self.acquireWriter(&rpc_ctx, gpa);
            defer self.releaseWriter(writer);

            try (net.Packet{
                .len = @intCast(u32, @sizeOf([32]u8) * ids.len),
                .nonce = nonce,
                .op = .request,
                .tag = .pull_transaction,
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

    pub fn pushTransactions(self: *Client, ctx: *Context, gpa: mem.Allocator, transactions: []const *Transaction, timeout_params: runtime.TimeoutParams) !void {
        var len: u32 = 0;
        for (transactions) |tx| {
            len += tx.size();
        }

        var rpc_ctx: Context = .{};
        defer rpc_ctx.cancel();

        var callback: struct {
            state: Context.Callback = .{ .run = @This().run },
            rpc_ctx: *Context,

            pub fn run(state: *Context.Callback) void {
                const callback = @fieldParentPtr(@This(), "state", state);
                callback.rpc_ctx.cancel();
            }
        } = .{ .rpc_ctx = &rpc_ctx };

        try ctx.register(&callback.state);
        defer ctx.deregister(&callback.state);

        var timeout: Context.Timeout = undefined;
        timeout.init(&rpc_ctx, timeout_params);
        defer timeout.deinit();

        {
            const writer = try self.acquireWriter(&rpc_ctx, gpa);
            defer self.releaseWriter(writer);

            try (net.Packet{
                .len = len,
                .nonce = 0,
                .op = .command,
                .tag = .push_transaction,
            }).write(writer);

            for (transactions) |tx| {
                try tx.write(writer);
            }
        }
    }
};

pub const Listener = struct {
    const log = std.log.scoped(.node_listener);

    pub const Connection = struct {
        base: *net.Listener(Listener).Connection,
        id: ?kademlia.ID = null,
    };

    node: *Node,

    pub fn serve(ctx: *Context, gpa: mem.Allocator, net_listener: *net.Listener(Listener), listener: tcp.Listener) !void {
        const bind_address = try listener.getLocalAddress();

        log.info("listening for peers: {}", .{bind_address});
        defer log.info("stopped listening for peers: {}", .{bind_address});

        return net_listener.serve(ctx, gpa, listener);
    }

    pub fn runReadLoop(self: Listener, ctx: *Context, gpa: mem.Allocator, base: *net.Listener(Listener).Connection) !void {
        var conn: Listener.Connection = .{ .base = base };

        var stream: runtime.Stream = .{ .socket = conn.base.client.socket, .context = ctx };
        var reader = stream.reader();

        var buffer = std.fifo.LinearFifo(u8, .Dynamic).init(gpa);
        defer buffer.deinit();

        while (true) {
            while (buffer.count < net.Packet.size) {
                const num_bytes = try reader.read(try buffer.writableWithSize(65536));
                if (num_bytes == 0) return;
                buffer.update(num_bytes);
            }

            const packet = try net.Packet.read(buffer.reader());

            while (buffer.count < packet.len) {
                const num_bytes = try reader.read(try buffer.writableWithSize(65536));
                if (num_bytes == 0) return;
                buffer.update(num_bytes);
            }

            var frame = io.limitedReader(buffer.reader(), packet.len);

            while (conn.base.buffer.items.len > 65536) {
                try conn.base.write_parker.park(ctx);
            }

            try self.process(ctx, gpa, &conn, packet, &frame);

            if (conn.base.buffer.items.len > 0) {
                conn.base.writer_parker.notify({});
            }
        }
    }

    pub fn runWriteLoop(self: Listener, ctx: *Context, gpa: mem.Allocator, conn: *net.Listener(Listener).Connection) !void {
        _ = self;
        _ = gpa;

        var stream: runtime.Stream = .{ .socket = conn.client.socket, .context = ctx };
        var writer = stream.writer();

        while (true) {
            while (conn.buffer.items.len == 0) {
                try conn.writer_parker.park(ctx);
            }

            const buffer = conn.buffer.toOwnedSlice();
            defer gpa.free(buffer);

            try writer.writeAll(buffer);
            conn.write_parker.notify({});
        }
    }

    fn process(
        self: Listener,
        ctx: *Context,
        gpa: mem.Allocator,
        conn: *Listener.Connection,
        packet: net.Packet,
        frame: anytype,
    ) !void {
        if (conn.id) |peer_id| {
            switch (self.node.table.put(peer_id)) {
                .full => conn.id = null,
                .updated, .inserted => {},
            }
        }

        switch (packet.op) {
            .request => {
                switch (packet.tag) {
                    .ping => {
                        try (net.Packet{
                            .len = "hello world".len,
                            .nonce = packet.nonce,
                            .op = .response,
                            .tag = .ping,
                        }).write(conn.base.buffer.writer());

                        try conn.base.buffer.writer().writeAll("hello world");
                    },
                    .hello => {
                        if (conn.id) |peer_id| {
                            log.warn("{} attempted to handshake twice from the same connection", .{peer_id});
                            return error.AlreadyHandshaked;
                        }

                        if (packet.len > 0) {
                            const peer_id = try kademlia.ID.read(frame.reader());
                            const signature = try frame.reader().readBytesNoEof(64);
                            try crypto.verify(signature, peer_id, peer_id.public_key);

                            switch (self.node.table.put(peer_id)) {
                                .full => log.info("incoming handshake from {} (peer ignored)", .{peer_id}),
                                .updated => {
                                    log.info("incoming handshake from {} (peer updated)", .{peer_id});
                                    conn.id = peer_id;
                                },
                                .inserted => {
                                    log.info("incoming handshake from {} (peer registered)", .{peer_id});
                                    conn.id = peer_id;
                                },
                            }
                        }

                        try (net.Packet{
                            .len = self.node.id.size(),
                            .nonce = packet.nonce,
                            .op = .response,
                            .tag = .hello,
                        }).write(conn.base.buffer.writer());

                        try self.node.id.write(conn.base.buffer.writer());
                    },
                    .find_node => {
                        const public_key = try frame.reader().readBytesNoEof(32);

                        var ids: [16]kademlia.ID = undefined;
                        const num_ids = self.node.table.closestTo(&ids, public_key);

                        var len: u32 = 0;
                        for (ids[0..num_ids]) |id| {
                            len += id.size();
                        }

                        try (net.Packet{
                            .len = len,
                            .nonce = packet.nonce,
                            .op = .response,
                            .tag = .find_node,
                        }).write(conn.base.buffer.writer());

                        for (ids[0..num_ids]) |id| {
                            try id.write(conn.base.buffer.writer());
                        }
                    },
                    .pull_transaction => {
                        var transactions: std.ArrayListUnmanaged(*Transaction) = .{};
                        defer {
                            for (transactions.items) |tx| {
                                tx.deinit(gpa);
                            }
                            transactions.deinit(gpa);
                        }

                        var pooled_conn = try self.node.chain.store.acquireConnection();
                        defer self.node.chain.store.releaseConnection(&pooled_conn);

                        var num_bytes: u32 = 0;
                        while (true) {
                            const tx_id = frame.reader().readBytesNoEof(32) catch |err| switch (err) {
                                error.EndOfStream => break,
                                else => return err,
                            };

                            var maybe_tx = self.node.chain.pending.get(tx_id);
                            if (maybe_tx == null) {
                                maybe_tx = try self.node.chain.store.getTransactionById(gpa, &pooled_conn, tx_id);
                            }

                            const tx = maybe_tx orelse continue;

                            transactions.append(gpa, tx.ref()) catch {
                                tx.deinit(gpa);
                                continue;
                            };

                            num_bytes += tx.size();
                        }

                        try (net.Packet{
                            .len = num_bytes,
                            .nonce = packet.nonce,
                            .op = .response,
                            .tag = .pull_transaction,
                        }).write(conn.base.buffer.writer());

                        for (transactions.items) |tx| {
                            try tx.write(conn.base.buffer.writer());
                        }
                    },
                    .pull_block => {
                        const requested_height = try frame.reader().readIntLittle(u64);
                        const requested_cache_id = frame.reader().readBytesNoEof(32) catch null;
                        const latest_height = if (self.node.chain.blocks.latest()) |latest_block| latest_block.height else 0;

                        const requested_block = block: {
                            if (requested_height == latest_height + 1) {
                                if (self.node.chain.sampler.preferred) |preferred_block| {
                                    break :block preferred_block.ref();
                                }
                                break :block null;
                            }
                            if (self.node.chain.blocks.get(requested_height)) |old_block| {
                                break :block old_block.ref();
                            }

                            var pooled_conn = try self.node.chain.store.acquireConnection();
                            defer self.node.chain.store.releaseConnection(&pooled_conn);

                            if (try self.node.chain.store.getBlockByHeight(gpa, &pooled_conn, requested_height)) |old_block| {
                                break :block old_block;
                            }
                            break :block null;
                        };
                        defer if (requested_block) |block| block.deinit(gpa);

                        const cache_hit = cache_hit: {
                            const cache_id = requested_cache_id orelse break :cache_hit false;
                            const block = requested_block orelse break :cache_hit false;
                            break :cache_hit mem.eql(u8, &block.id, &cache_id);
                        };

                        var len: u32 = 1;
                        if (requested_block) |block| {
                            if (!cache_hit) {
                                len += block.size();
                            }
                        }

                        try (net.Packet{
                            .len = len,
                            .nonce = packet.nonce,
                            .op = .response,
                            .tag = .pull_block,
                        }).write(conn.base.buffer.writer());

                        if (requested_block) |block| {
                            try conn.base.buffer.writer().writeByte(1);
                            if (!cache_hit) {
                                try block.write(conn.base.buffer.writer());
                            }
                        } else {
                            try conn.base.buffer.writer().writeByte(0);
                        }
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
                        }).write(conn.base.buffer.writer());

                        try conn.base.buffer.writer().writeAll("hello world");
                    },
                    .push_transaction => {
                        var count: usize = 0;
                        while (true) : (count += 1) {
                            const tx = Transaction.read(gpa, frame.reader()) catch |err| switch (err) {
                                error.EndOfStream => break,
                                else => return err,
                            };
                            defer tx.deinit(gpa);

                            // do not push transactions we receive from a peer back

                            if (conn.id) |peer_id| {
                                if (self.node.pusher.isAlreadyGossipedToPeer(peer_id.address, tx.id)) {
                                    continue;
                                }
                            }

                            self.node.verifier.push(ctx, gpa, tx.ref()) catch {
                                tx.deinit(gpa);
                                continue;
                            };
                        }
                    },
                    else => return error.UnexpectedTag,
                }
            },
            .response => return error.UnexpectedPacket,
        }
    }
};

pub const HttpHandler = struct {
    node: *Node,

    pub usingnamespace http.router.build(HttpHandler, .{
        http.router.get("/", index),
        http.router.get("/blocks", getBlocks),
        http.router.get("/transactions", getTransactions),
        http.router.get("/database/:query", queryDatabase),

        http.router.post("/transactions", submitTransaction),

        http.router.put("/whitelist", addToWhitelist),
        http.router.delete("/whitelist", removeFromWhitelist),
    });

    pub fn addToWhitelist(
        self: HttpHandler,
        ctx: *Context,
        gpa: mem.Allocator,
        req: http.Request,
        reader: anytype,
        writer: anytype,
        _: []http.router.Param,
    ) !void {
        _ = ctx;

        const content_length = for (req.getHeaders()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
                break try fmt.parseInt(usize, header.value, 10);
            }
        } else return error.ContentLengthExpected;

        if (content_length > 512 * 1024) {
            return error.ContentLengthMustBeLessThan512kb;
        }

        const body: []u8 = try reader.readAllAlloc(gpa, content_length);
        defer gpa.free(body);

        var tokens = std.json.TokenStream.init(body);

        const Request = struct {
            public_key: [Ed25519.public_length * 2]u8,
            signature: [Ed25519.signature_length * 2]u8,
            target_public_key: [Ed25519.public_length * 2]u8,
            timestamp: i64,
        };

        const request = try std.json.parse(Request, &tokens, .{});
        defer std.json.parseFree(Request, request, .{});

        const current_time = @divTrunc(std.time.milliTimestamp(), std.time.ms_per_s);
        const lower_bound = try std.math.sub(i64, current_time, 10 * std.time.s_per_min);
        const upper_bound = try std.math.add(i64, current_time, 10 * std.time.s_per_min);
        if (request.timestamp < lower_bound) return error.RequestTooOld;
        if (request.timestamp > upper_bound) return error.RequestTooNew;

        var public_key: [Ed25519.public_length]u8 = undefined;
        _ = try std.fmt.hexToBytes(&public_key, &request.public_key);

        var signature: [Ed25519.signature_length]u8 = undefined;
        _ = try std.fmt.hexToBytes(&signature, &request.signature);

        var target_public_key: [Ed25519.public_length]u8 = undefined;
        _ = try std.fmt.hexToBytes(&target_public_key, &request.target_public_key);

        const message = mem.nativeToLittle(i64, request.timestamp);
        try Ed25519.verify(signature, mem.asBytes(&message), public_key);

        const is_whitelisted = is_whitelisted: {
            var conn = try self.node.chain.store.acquireConnection();
            defer self.node.chain.store.releaseConnection(&conn);

            runtime.startCpuBoundOperation();
            defer runtime.endCpuBoundOperation();

            break :is_whitelisted self.node.chain.store.isPublicKeyWhitelisted(&conn, public_key);
        };

        if (!is_whitelisted) {
            return error.UserNotWhitelisted;
        }

        {
            var conn = try self.node.chain.store.acquireConnection();
            defer self.node.chain.store.releaseConnection(&conn);

            runtime.startCpuBoundOperation();
            defer runtime.endCpuBoundOperation();

            try self.node.chain.store.addPublicKeyToWhitelist(&conn, target_public_key);
        }

        const response_message = "{\"status: \"ok\"}";

        const response: http.Response = .{
            .status_code = 200,
            .message = "OK",
            .headers = &[_]http.Header{
                .{ .name = "Content-Type", .value = "application/json" },
                .{ .name = "Content-Length", .value = std.fmt.comptimePrint("{d}", .{response_message.len}) },
            },
            .num_headers = 2,
        };

        try writer.print("{}", .{response});
        try writer.writeAll(response_message);
    }

    pub fn removeFromWhitelist(
        self: HttpHandler,
        ctx: *Context,
        gpa: mem.Allocator,
        req: http.Request,
        reader: anytype,
        writer: anytype,
        _: []http.router.Param,
    ) !void {
        _ = ctx;

        const content_length = for (req.getHeaders()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
                break try fmt.parseInt(usize, header.value, 10);
            }
        } else return error.ContentLengthExpected;

        if (content_length > 512 * 1024) {
            return error.ContentLengthMustBeLessThan512kb;
        }

        const body: []u8 = try reader.readAllAlloc(gpa, content_length);
        defer gpa.free(body);

        var tokens = std.json.TokenStream.init(body);

        const Request = struct {
            public_key: [Ed25519.public_length * 2]u8,
            signature: [Ed25519.signature_length * 2]u8,
            target_public_key: [Ed25519.public_length * 2]u8,
            timestamp: i64,
        };

        const request = try std.json.parse(Request, &tokens, .{});
        defer std.json.parseFree(Request, request, .{});

        const current_time = @divTrunc(std.time.milliTimestamp(), std.time.ms_per_s);
        const lower_bound = try std.math.sub(i64, current_time, 10 * std.time.s_per_min);
        const upper_bound = try std.math.add(i64, current_time, 10 * std.time.s_per_min);
        if (request.timestamp < lower_bound) return error.RequestTooOld;
        if (request.timestamp > upper_bound) return error.RequestTooNew;

        var public_key: [Ed25519.public_length]u8 = undefined;
        _ = try std.fmt.hexToBytes(&public_key, &request.public_key);

        var signature: [Ed25519.signature_length]u8 = undefined;
        _ = try std.fmt.hexToBytes(&signature, &request.signature);

        var target_public_key: [Ed25519.public_length]u8 = undefined;
        _ = try std.fmt.hexToBytes(&target_public_key, &request.target_public_key);

        const message = mem.nativeToLittle(i64, request.timestamp);
        try Ed25519.verify(signature, mem.asBytes(&message), public_key);

        const is_whitelisted = is_whitelisted: {
            var conn = try self.node.chain.store.acquireConnection();
            defer self.node.chain.store.releaseConnection(&conn);

            runtime.startCpuBoundOperation();
            defer runtime.endCpuBoundOperation();

            break :is_whitelisted self.node.chain.store.isPublicKeyWhitelisted(&conn, public_key);
        };

        if (!is_whitelisted) {
            return error.UserNotWhitelisted;
        }

        const deleted = result: {
            var conn = try self.node.chain.store.acquireConnection();
            defer self.node.chain.store.releaseConnection(&conn);

            runtime.startCpuBoundOperation();
            defer runtime.endCpuBoundOperation();

            break :result self.node.chain.store.removePublicKeyFromWhitelist(&conn, target_public_key);
        };

        if (deleted) {
            const response_message = "{\"status: \"deleted\"}";

            const response: http.Response = .{
                .status_code = 200,
                .message = "OK",
                .headers = &[_]http.Header{
                    .{ .name = "Content-Type", .value = "application/json" },
                    .{ .name = "Content-Length", .value = std.fmt.comptimePrint("{d}", .{response_message.len}) },
                },
                .num_headers = 2,
            };

            try writer.print("{}", .{response});
            try writer.writeAll(response_message);
        } else {
            const response_message = "{\"status: \"public key not whitelisted\"}";

            const response: http.Response = .{
                .status_code = 200,
                .message = "OK",
                .headers = &[_]http.Header{
                    .{ .name = "Content-Type", .value = "application/json" },
                    .{ .name = "Content-Length", .value = std.fmt.comptimePrint("{d}", .{response_message.len}) },
                },
                .num_headers = 2,
            };

            try writer.print("{}", .{response});
            try writer.writeAll(response_message);
        }
    }

    pub fn index(
        self: HttpHandler,
        ctx: *Context,
        gpa: mem.Allocator,
        request: http.Request,
        reader: anytype,
        writer: anytype,
        params: []http.router.Param,
    ) !void {
        _ = self;
        _ = ctx;
        _ = gpa;
        _ = request;
        _ = reader;
        _ = params;

        var buffer = std.ArrayList(u8).init(gpa);
        defer buffer.deinit();

        var peer_ids: [16]kademlia.ID = undefined;
        const num_peer_ids = self.node.table.closestTo(&peer_ids, self.node.id.public_key);

        var stream = std.json.writeStream(buffer.writer(), 128);
        var buf: [1024]u8 = undefined;

        try stream.beginObject();

        try stream.objectField("id");
        try stream.beginObject();
        try stream.objectField("public_key");
        try stream.emitString(try fmt.bufPrint(&buf, "{}", .{fmt.fmtSliceHexLower(&self.node.id.public_key)}));
        try stream.objectField("address");
        try stream.emitString(try fmt.bufPrint(&buf, "{}", .{self.node.id.address}));
        try stream.endObject();

        try stream.objectField("database_path");
        try stream.emitString(if (self.node.chain.store.maybe_path) |path| path else ":memory:");

        try stream.objectField("current_block_height");
        try stream.emitNumber(if (self.node.chain.blocks.latest()) |latest_block| latest_block.height else 0);

        try stream.objectField("num_pending_transactions");
        try stream.emitNumber(self.node.chain.pending.len);

        try stream.objectField("num_missing_transactions");
        try stream.emitNumber(self.node.chain.missing.len);

        try stream.objectField("peer_ids");
        try stream.beginArray();
        for (peer_ids[0..num_peer_ids]) |peer_id| {
            try stream.arrayElem();
            try stream.beginObject();
            try stream.objectField("public_key");
            try stream.emitString(try fmt.bufPrint(&buf, "{}", .{fmt.fmtSliceHexLower(&peer_id.public_key)}));
            try stream.objectField("address");
            try stream.emitString(try fmt.bufPrint(&buf, "{}", .{peer_id.address}));
            try stream.endObject();
        }
        try stream.endArray();

        try stream.endObject();

        const response: http.Response = .{
            .status_code = 200,
            .message = "OK",
            .headers = &[_]http.Header{
                .{ .name = "Content-Type", .value = "application/json" },
                .{ .name = "Content-Length", .value = fmt.bufPrintIntToSlice(&buf, buffer.items.len, 10, .lower, .{}) },
            },
            .num_headers = 2,
        };

        try writer.print("{}", .{response});
        try writer.print("{s}", .{buffer.items});
    }

    pub fn getBlocks(
        self: HttpHandler,
        ctx: *Context,
        gpa: mem.Allocator,
        request: http.Request,
        reader: anytype,
        writer: anytype,
        params: []http.router.Param,
    ) !void {
        _ = self;
        _ = ctx;
        _ = gpa;
        _ = request;
        _ = reader;
        _ = params;

        const uri = try http.Uri.parse(request.path, true);

        var query = try http.Uri.mapQuery(gpa, uri.query);
        defer query.deinit();

        var body = std.ArrayList(u8).init(gpa);
        defer body.deinit();

        var content = io.countingWriter(body.writer());
        var length_buf: [16]u8 = undefined;

        if (query.get("id")) |id_hex| {
            if (id_hex.len != 64) {
                return error.BadBlockId;
            }

            var id: [32]u8 = undefined;
            _ = try fmt.hexToBytes(&id, id_hex);

            const maybe_block_result = maybe_block: {
                var conn = try self.node.chain.store.acquireConnection();
                defer self.node.chain.store.releaseConnection(&conn);

                runtime.startCpuBoundOperation();
                defer runtime.endCpuBoundOperation();

                break :maybe_block self.node.chain.store.getBlockById(gpa, &conn, id);
            };

            const maybe_block = try maybe_block_result;
            defer if (maybe_block) |block| block.deinit(gpa);

            const block = maybe_block orelse return error.BlockNotFound;
            try std.json.stringify(block, .{}, content.writer());

            const response: http.Response = .{
                .status_code = 200,
                .message = "OK",
                .headers = &[_]http.Header{
                    .{
                        .name = "Content-Type",
                        .value = "application/json",
                    },
                    .{
                        .name = "Content-Length",
                        .value = fmt.bufPrintIntToSlice(&length_buf, content.bytes_written, 10, .lower, .{}),
                    },
                },
                .num_headers = 2,
            };

            try writer.print("{}", .{response});
            try std.json.stringify(block, .{}, writer);
        } else if (query.get("height")) |height_text| {
            const height = try fmt.parseUnsigned(u64, height_text, 10);

            const maybe_block_result = maybe_block: {
                var conn = try self.node.chain.store.acquireConnection();
                defer self.node.chain.store.releaseConnection(&conn);

                runtime.startCpuBoundOperation();
                defer runtime.endCpuBoundOperation();

                break :maybe_block self.node.chain.store.getBlockByHeight(gpa, &conn, height);
            };

            const maybe_block = try maybe_block_result;
            defer if (maybe_block) |block| block.deinit(gpa);

            const block = maybe_block orelse return error.BlockNotFound;
            try std.json.stringify(block, .{}, content.writer());

            const response: http.Response = .{
                .status_code = 200,
                .message = "OK",
                .headers = &[_]http.Header{
                    .{
                        .name = "Content-Type",
                        .value = "application/json",
                    },
                    .{
                        .name = "Content-Length",
                        .value = fmt.bufPrintIntToSlice(&length_buf, content.bytes_written, 10, .lower, .{}),
                    },
                },
                .num_headers = 2,
            };

            try writer.print("{}", .{response});
            try std.json.stringify(block, .{}, writer);
        } else {
            const offset = if (query.get("offset")) |text| try fmt.parseInt(usize, text, 10) else 0;
            const limit = math.min(100, if (query.get("limit")) |text| try fmt.parseInt(usize, text, 10) else 100);

            const blocks_result = blocks: {
                var conn = try self.node.chain.store.acquireConnection();
                defer self.node.chain.store.releaseConnection(&conn);

                runtime.startCpuBoundOperation();
                defer runtime.endCpuBoundOperation();

                break :blocks self.node.chain.store.getBlockSummaries(gpa, &conn, offset, limit);
            };

            const blocks = try blocks_result;
            defer gpa.free(blocks);

            try std.json.stringify(blocks, .{}, content.writer());

            const response: http.Response = .{
                .status_code = 200,
                .message = "OK",
                .headers = &[_]http.Header{
                    .{
                        .name = "Content-Type",
                        .value = "application/json",
                    },
                    .{
                        .name = "Content-Length",
                        .value = fmt.bufPrintIntToSlice(&length_buf, content.bytes_written, 10, .lower, .{}),
                    },
                },
                .num_headers = 2,
            };

            try writer.print("{}", .{response});
            try std.json.stringify(blocks, .{}, writer);
        }
    }

    pub fn getTransactions(
        self: HttpHandler,
        ctx: *Context,
        gpa: mem.Allocator,
        request: http.Request,
        reader: anytype,
        writer: anytype,
        params: []http.router.Param,
    ) !void {
        _ = self;
        _ = ctx;
        _ = gpa;
        _ = request;
        _ = reader;
        _ = params;

        const uri = try http.Uri.parse(request.path, true);

        var query = try http.Uri.mapQuery(gpa, uri.query);
        defer query.deinit();

        var body = std.ArrayList(u8).init(gpa);
        defer body.deinit();

        var content = io.countingWriter(body.writer());
        var length_buf: [16]u8 = undefined;

        if (query.get("id")) |id_hex| {
            if (id_hex.len != 64) {
                return error.BadTransactionId;
            }

            var id: [32]u8 = undefined;
            _ = try fmt.hexToBytes(&id, id_hex);

            const maybe_tx_result = maybe_tx: {
                var conn = try self.node.chain.store.acquireConnection();
                defer self.node.chain.store.releaseConnection(&conn);

                runtime.startCpuBoundOperation();
                defer runtime.endCpuBoundOperation();

                break :maybe_tx self.node.chain.store.getTransactionById(gpa, &conn, id);
            };

            const maybe_tx = try maybe_tx_result;
            defer if (maybe_tx) |tx| tx.deinit(gpa);

            const tx = maybe_tx orelse return error.TransactionNotFound;
            try std.json.stringify(tx, .{}, content.writer());

            const response: http.Response = .{
                .status_code = 200,
                .message = "OK",
                .headers = &[_]http.Header{
                    .{
                        .name = "Content-Type",
                        .value = "application/json",
                    },
                    .{
                        .name = "Content-Length",
                        .value = fmt.bufPrintIntToSlice(&length_buf, content.bytes_written, 10, .lower, .{}),
                    },
                },
                .num_headers = 2,
            };

            try writer.print("{}", .{response});
            try std.json.stringify(tx, .{}, writer);
        } else if (query.get("block_height")) |block_height_text| {
            const block_height = try fmt.parseUnsigned(u64, block_height_text, 10);
            const offset = if (query.get("offset")) |text| try fmt.parseInt(usize, text, 10) else 0;
            const limit = math.min(100, if (query.get("limit")) |text| try fmt.parseInt(usize, text, 10) else 100);

            const transactions_result = transactions: {
                var conn = try self.node.chain.store.acquireConnection();
                defer self.node.chain.store.releaseConnection(&conn);

                runtime.startCpuBoundOperation();
                defer runtime.endCpuBoundOperation();

                break :transactions self.node.chain.store.getTransactionsByBlockHeight(gpa, &conn, block_height, offset, limit);
            };

            const transactions = try transactions_result;
            defer {
                for (transactions) |tx| {
                    tx.deinit(gpa);
                }
                gpa.free(transactions);
            }

            try std.json.stringify(transactions, .{}, content.writer());

            const response: http.Response = .{
                .status_code = 200,
                .message = "OK",
                .headers = &[_]http.Header{
                    .{
                        .name = "Content-Type",
                        .value = "application/json",
                    },
                    .{
                        .name = "Content-Length",
                        .value = fmt.bufPrintIntToSlice(&length_buf, content.bytes_written, 10, .lower, .{}),
                    },
                },
                .num_headers = 2,
            };

            try writer.print("{}", .{response});
            try std.json.stringify(transactions, .{}, writer);
        } else {
            const offset = if (query.get("offset")) |text| try fmt.parseInt(usize, text, 10) else 0;
            const limit = math.min(100, if (query.get("limit")) |text| try fmt.parseInt(usize, text, 10) else 100);

            const transactions_result = transactions: {
                var conn = try self.node.chain.store.acquireConnection();
                defer self.node.chain.store.releaseConnection(&conn);

                runtime.startCpuBoundOperation();
                defer runtime.endCpuBoundOperation();

                break :transactions self.node.chain.store.getTransactions(gpa, &conn, offset, limit);
            };

            const transactions = try transactions_result;
            defer {
                for (transactions) |tx| {
                    tx.deinit(gpa);
                }
                gpa.free(transactions);
            }

            try std.json.stringify(transactions, .{}, content.writer());

            const response: http.Response = .{
                .status_code = 200,
                .message = "OK",
                .headers = &[_]http.Header{
                    .{
                        .name = "Content-Type",
                        .value = "application/json",
                    },
                    .{
                        .name = "Content-Length",
                        .value = fmt.bufPrintIntToSlice(&length_buf, content.bytes_written, 10, .lower, .{}),
                    },
                },
                .num_headers = 2,
            };

            try writer.print("{}", .{response});
            try std.json.stringify(transactions, .{}, writer);
        }
    }

    pub fn queryDatabase(
        self: HttpHandler,
        ctx: *Context,
        gpa: mem.Allocator,
        request: http.Request,
        reader: anytype,
        writer: anytype,
        params: []const http.router.Param,
    ) !void {
        _ = self;
        _ = ctx;
        _ = gpa;
        _ = request;
        _ = reader;

        const query = (try http.Uri.decode(gpa, params[0].value)) orelse return error.QueryNotEncoded;
        defer gpa.free(query);

        const query_result = query: {
            var conn = try self.node.chain.store.acquireConnection();
            defer self.node.chain.store.releaseConnection(&conn);

            runtime.startCpuBoundOperation();
            defer runtime.endCpuBoundOperation();

            break :query self.node.chain.store.queryJson(gpa, &conn, query);
        };

        const result = try query_result;
        defer gpa.free(result);

        var length_buf: [128]u8 = undefined;

        const response: http.Response = .{
            .status_code = 200,
            .message = "OK",
            .headers = &[_]http.Header{
                .{ .name = "Content-Type", .value = "application/json" },
                .{ .name = "Content-Length", .value = fmt.bufPrintIntToSlice(&length_buf, result.len, 10, .lower, .{}) },
            },
            .num_headers = 2,
        };

        try writer.print("{}", .{response});
        try writer.writeAll(result);
    }

    pub fn submitTransaction(
        self: HttpHandler,
        ctx: *Context,
        gpa: mem.Allocator,
        request: http.Request,
        reader: anytype,
        writer: anytype,
        params: []http.router.Param,
    ) !void {
        _ = self;
        _ = ctx;
        _ = gpa;
        _ = request;
        _ = reader;
        _ = params;

        const content_length = for (request.getHeaders()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
                break try fmt.parseInt(usize, header.value, 10);
            }
        } else return error.ContentLengthExpected;

        var body = io.limitedReader(reader, content_length);

        const tx = try Transaction.read(gpa, body.reader());
        defer tx.deinit(gpa);

        const is_whitelisted = is_whitelisted: {
            var conn = try self.node.chain.store.acquireConnection();
            defer self.node.chain.store.releaseConnection(&conn);

            runtime.startCpuBoundOperation();
            defer runtime.endCpuBoundOperation();

            break :is_whitelisted self.node.chain.store.isPublicKeyWhitelisted(&conn, tx.sender);
        };

        if (!is_whitelisted) {
            return error.UserNotWhitelisted;
        }

        self.node.verifier.push(ctx, gpa, tx.ref()) catch |err| {
            tx.deinit(gpa);
            return err;
        };

        var transaction_id_buf: [64]u8 = undefined;
        var length_buf: [16]u8 = undefined;

        const result = .{
            .result = "ok",
            .transaction_id = try fmt.bufPrint(&transaction_id_buf, "{}", .{fmt.fmtSliceHexLower(&tx.id)}),
        };

        var content = io.countingWriter(io.null_writer);
        try std.json.stringify(result, .{}, content.writer());

        const response: http.Response = .{
            .status_code = 200,
            .message = "OK",
            .headers = &[_]http.Header{
                .{ .name = "Content-Type", .value = "application/json" },
                .{ .name = "Content-Length", .value = fmt.bufPrintIntToSlice(&length_buf, content.bytes_written, 10, .lower, .{}) },
            },
            .num_headers = 2,
        };

        try writer.print("{}", .{response});
        try std.json.stringify(result, .{}, writer);
    }
};

pub const Node = struct {
    const log = std.log.scoped(.node);

    id: kademlia.ID,
    keys: Ed25519.KeyPair,

    chain: Chain(SqliteStore),
    pusher: TransactionPusher,
    puller: TransactionPuller,
    verifier: TransactionVerifier,
    clients: std.HashMapUnmanaged(ip.Address, *Client, struct {
        pub fn hash(_: @This(), address: ip.Address) u64 {
            return net.hashIpAddress(address);
        }

        pub fn eql(_: @This(), a: ip.Address, b: ip.Address) bool {
            return net.eqlIpAddress(a, b);
        }
    }, std.hash_map.default_max_load_percentage),
    table: kademlia.RoutingTable,
    closed: bool = false,

    pub fn init(self: *Node, gpa: mem.Allocator, store: *SqliteStore, keys: Ed25519.KeyPair, address: ip.Address) !void {
        self.keys = keys;
        self.id = .{ .public_key = keys.public_key, .address = address };

        self.chain = try Chain(SqliteStore).init(gpa, store);
        errdefer self.chain.deinit(gpa);

        self.pusher = try TransactionPusher.init(gpa, self);
        self.puller = TransactionPuller.init(self);
        self.verifier = TransactionVerifier.init(self);

        self.clients = .{};
        self.table = .{ .public_key = keys.public_key };
    }

    pub fn deinit(self: *Node, ctx: *Context, gpa: mem.Allocator) void {
        log.info("shutting down...", .{});

        self.closed = true;

        var client_it = self.clients.valueIterator();
        while (client_it.next()) |client_ptr| {
            log.info("shutting down client {}...", .{client_ptr.*.base.address});

            if (client_ptr.*.deinit(ctx, gpa)) |_| {
                log.info("client {} successfully shut down", .{client_ptr.*.base.address});
            } else |err| {
                log.warn("client {} reported an error while shutting down: {}", .{ client_ptr.*.base.address, err });
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

    pub fn getOrCreateClient(self: *Node, ctx: *Context, gpa: mem.Allocator, address: ip.Address) !*Client {
        if (self.closed) return error.Closed;

        const result = try self.clients.getOrPut(gpa, address);
        if (!result.found_existing) {
            errdefer |err| log.warn("failed to handshake with {}: {}", .{ address, err });
            errdefer assert(self.clients.remove(address));

            result.value_ptr.* = try gpa.create(Client);
            errdefer gpa.destroy(result.value_ptr.*);

            result.value_ptr.*.* = try Client.init(gpa, address);
            errdefer result.value_ptr.*.deinit(ctx, gpa) catch {};

            const peer_id = try result.value_ptr.*.sayHello(ctx, gpa, self.keys, self.id, .{ .seconds = 5 });
            switch (self.table.put(peer_id)) {
                .full => log.info("handshaked with {} (peer ignored)", .{peer_id}),
                .updated => log.info("handshaked with {} (peer updated)", .{peer_id}),
                .inserted => log.info("handshaked with {} (peer registered)", .{peer_id}),
            }
        }

        return result.value_ptr.*;
    }

    pub fn acquireWriter(self: *Node, ctx: *Context, gpa: mem.Allocator, address: ip.Address) !std.ArrayList(u8).Writer {
        const client = try self.getOrCreateClient(ctx, gpa, address);
        return client.acquireWriter(ctx, gpa);
    }

    pub fn releaseWriter(self: *Node, address: ip.Address, writer: std.ArrayList(u8).Writer) void {
        const client = self.clients.get(address) orelse unreachable;
        return client.releaseWriter(writer);
    }

    pub fn run(self: *Node, ctx: *Context, gpa: mem.Allocator) !void {
        var pusher_frame = async self.pusher.run(ctx, gpa);
        defer await pusher_frame catch |err| if (err != error.Cancelled) log.warn("transaction pusher error: {}", .{err});

        var puller_frame = async self.puller.run(ctx, gpa);
        defer await puller_frame catch |err| if (err != error.Cancelled) log.warn("transaction puller error: {}", .{err});

        var verifier_frame = async self.verifier.run(ctx, gpa);
        defer await verifier_frame catch |err| if (err != error.Cancelled) log.warn("transaction verifier error: {}", .{err});

        var chain_frame = async self.chain.run(ctx, gpa, self);
        defer await chain_frame catch |err| if (err != error.Cancelled) log.warn("chain error: {}", .{err});
    }

    pub fn addTransaction(self: *Node, ctx: *Context, gpa: mem.Allocator, tx: *Transaction) !void {
        _ = self.chain.missing.delete(tx.id);

        if (self.chain.finalized.get(tx.id) != null or slow_path: {
            var conn = try self.chain.store.acquireConnection();
            defer self.chain.store.releaseConnection(&conn);
            break :slow_path self.chain.store.isTransactionFinalized(&conn, tx.id);
        }) {
            return error.AlreadyExists;
        }

        const result = try self.chain.pending.getOrPut(gpa, tx.id);
        if (result.found_existing) {
            return error.AlreadyExists;
        }
        result.value_ptr.* = tx;

        self.pusher.push(ctx, gpa, tx.ref()) catch |err| {
            tx.deinit(gpa);
            return err;
        };
    }
};

pub fn Chain(comptime Store: type) type {
    return struct {
        const log = std.log.scoped(.chain);

        const Self = @This();

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

        store: *Store,
        sampler: Sampler,
        pending: SortedHashMap(*Transaction, 50),
        missing: lru.AutoIntrusiveHashMap([32]u8, u64, 50),
        finalized: lru.AutoIntrusiveHashMap([32]u8, void, 50),

        /// 'head' and 'tail' are set at 1 until genesis blocks are implemented. Genesis
        /// blocks are blocks whose height is 0. Until they are implemented it is safe to
        /// assume that the first block that is to be pushed into this ring buffer starts
        /// at height 1.
        blocks: StaticRingBuffer(*Block, u64, 32),
        block_proposal_cache: lru.AutoIntrusiveHashMap(ip.Address, *Block, 50),

        propose_delay: i64 = propose_delay_min,
        connected_delay: i64 = connected_delay_min,

        pub fn init(gpa: mem.Allocator, store: *Store) !Self {
            var sampler = try Sampler.init(gpa);
            errdefer sampler.deinit(gpa);

            var pending = try SortedHashMap(*Transaction, 50).init(gpa);
            errdefer pending.deinit(gpa);

            var missing = try lru.AutoIntrusiveHashMap([32]u8, u64, 50).initCapacity(gpa, 1 << 16);
            errdefer missing.deinit(gpa);

            var finalized = try lru.AutoIntrusiveHashMap([32]u8, void, 50).initCapacity(gpa, 1 << 20);
            errdefer finalized.deinit(gpa);

            var block_proposal_cache = try lru.AutoIntrusiveHashMap(ip.Address, *Block, 50).initCapacity(gpa, 128);
            errdefer block_proposal_cache.deinit(gpa);

            var conn = try store.acquireConnection();
            defer store.releaseConnection(&conn);

            const cached_blocks = try store.getBlocks(gpa, &conn, 0, 32);
            defer {
                for (cached_blocks) |cached_block| {
                    cached_block.deinit(gpa);
                }
                gpa.free(cached_blocks);
            }

            var blocks: StaticRingBuffer(*Block, u64, 32) = .{ .head = 1, .tail = 1 };
            if (cached_blocks.len > 0) {
                blocks.head = cached_blocks[cached_blocks.len - 1].height;
                blocks.tail = cached_blocks[cached_blocks.len - 1].height;

                log.info("latest block is {} (height: {}, num transactions: {})", .{
                    fmt.fmtSliceHexLower(&cached_blocks[0].id),
                    cached_blocks[0].height,
                    cached_blocks[0].num_transaction_ids,
                });
            } else {
                log.info("no blocks found in store: starting off with an empty blockchain", .{});
            }

            var i: usize = cached_blocks.len;
            while (i > 0) : (i -= 1) {
                blocks.push(cached_blocks[i - 1].ref());
            }

            return Self{
                .store = store,
                .sampler = sampler,
                .pending = pending,
                .missing = missing,
                .finalized = finalized,
                .blocks = blocks,
                .block_proposal_cache = block_proposal_cache,
            };
        }

        pub fn deinit(self: *Self, gpa: mem.Allocator) void {
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
            self.finalized.deinit(gpa);

            while (self.blocks.popOrNull()) |block| {
                block.deinit(gpa);
            }

            self.sampler.deinit(gpa);

            log.info("successfully shut down", .{});
        }

        pub fn run(self: *Self, ctx: *Context, gpa: mem.Allocator, node: *Node) !void {
            // TODO: cleanup error handling in this function

            var transaction_ids: std.ArrayListUnmanaged([32]u8) = .{};
            defer transaction_ids.deinit(gpa);

            var block_proposals: BlockProposalMap = .{};
            defer block_proposals.deinit(gpa);

            try transaction_ids.ensureTotalCapacity(gpa, Block.max_num_transaction_ids);
            try block_proposals.ensureTotalCapacity(gpa, 32);

            var rng = std.rand.DefaultPrng.init(@bitCast(u64, time.timestamp()));

            // TODO: randomly sample peer ids from routing table instead
            var peer_ids: [16]kademlia.ID = undefined;

            while (true) {
                const num_peers = node.table.closestTo(&peer_ids, node.id.public_key);
                if (num_peers == 0) {
                    try runtime.timeout(ctx, .{ .nanoseconds = self.connected_delay });
                    self.connected_delay = math.min(connected_delay_max, self.connected_delay + (connected_delay_max - connected_delay_min) / 10);
                    continue;
                }

                self.connected_delay = connected_delay_min;

                const preferred_block = self.sampler.preferred orelse {
                    self.proposeBlock(ctx, gpa, &transaction_ids) catch |err| switch (err) {
                        error.NoTransactionsToPropose => {
                            const next_block_height = (if (self.blocks.latest()) |latest_block| latest_block.height else 0) + 1;
                            try self.pullBlockProposals(ctx, gpa, node, null, peer_ids[0..num_peers], next_block_height);
                        },
                        else => return err,
                    };
                    continue;
                };

                defer block_proposals.clearRetainingCapacity();

                // sample block proposals proposals and tally them

                try self.pullBlockProposals(ctx, gpa, node, &block_proposals, peer_ids[0..num_peers], preferred_block.height);

                // steal a valid block proposal to be our preferred block proposal if there are any valid ones that seem promising

                var max_block_proposal: ?*Block = null;
                var block_proposals_it = block_proposals.keyIterator();
                while (block_proposals_it.next()) |block_ptr| {
                    const block: *Block = block_ptr.* orelse continue;
                    if (max_block_proposal == null or block.num_transaction_ids > max_block_proposal.?.num_transaction_ids) {
                        max_block_proposal = block;
                    }
                }

                if (max_block_proposal) |block_proposal| {
                    if (!mem.eql(u8, &preferred_block.id, &block_proposal.id) and ((self.sampler.stalled >= Sampler.default_beta and rng.random().boolean()) or block_proposal.num_transaction_ids > preferred_block.num_transaction_ids)) {
                        log.debug("moved from block {} (height: {}, {} transaction(s)) to block {} (height: {}, {} transaction(s))", .{
                            fmt.fmtSliceHexLower(&preferred_block.id),
                            preferred_block.height,
                            preferred_block.num_transaction_ids,
                            fmt.fmtSliceHexLower(&block_proposal.id),
                            block_proposal.height,
                            block_proposal.num_transaction_ids,
                        });

                        self.sampler.reset(gpa);
                        self.sampler.prefer(gpa, block_proposal.ref());

                        continue;
                    }
                }

                // tally our own preferred block proposal

                const result = block_proposals.getOrPutAssumeCapacity(preferred_block);
                if (!result.found_existing) {
                    result.value_ptr.* = 0;
                }
                result.value_ptr.* += 1;

                // group block proposal tallies together by block id

                var votes: [16]Sampler.Vote = undefined;
                var num_votes: usize = 0;

                var blocks_it = block_proposals.iterator();
                while (blocks_it.next()) |entry| : (num_votes += 1) {
                    const count = @intToFloat(f64, entry.value_ptr.*);
                    const total = @intToFloat(f64, num_peers + 1);
                    votes[num_votes] = .{ .block = entry.key_ptr.*, .tally = count / total };
                }

                // update the block sampler

                // if the block sampler concludes that a block has been finalized, mark all transactions in
                // the block by their id to have been finalized, store the block on-disk, and reset the
                // block sampler

                const finalized_block = (try self.sampler.update(gpa, &votes)) orelse continue;
                defer {
                    var it = self.block_proposal_cache.head;
                    while (it) |entry| : (it = entry.next) {
                        entry.value.deinit(gpa);
                    }
                    self.block_proposal_cache.clear();

                    self.sampler.reset(gpa);
                }

                var finalized_transactions: std.ArrayListUnmanaged(*Transaction) = .{};
                defer finalized_transactions.deinit(gpa);

                try finalized_transactions.ensureUnusedCapacity(gpa, finalized_block.num_transaction_ids);

                for (finalized_block.transaction_ids[0..finalized_block.num_transaction_ids]) |tx_id| {
                    finalized_transactions.appendAssumeCapacity(self.pending.get(tx_id).?);
                }

                const store_block_result = store_block: {
                    var conn = try self.store.acquireConnection();
                    defer self.store.releaseConnection(&conn);

                    runtime.startCpuBoundOperation();
                    defer runtime.endCpuBoundOperation();

                    break :store_block self.store.storeBlock(gpa, &conn, finalized_block, finalized_transactions.items);
                };

                store_block_result catch |err| {
                    log.warn("failed to save block {} (height {}, {} transaction(s): {}", .{
                        fmt.fmtSliceHexLower(&finalized_block.id),
                        finalized_block.height,
                        finalized_block.num_transaction_ids,
                        err,
                    });
                    continue;
                };

                for (finalized_block.transaction_ids[0..finalized_block.num_transaction_ids]) |tx_id| {
                    _ = self.finalized.update(tx_id, .{});
                    self.pending.delete(tx_id).?.deinit(gpa);
                }

                if (self.blocks.pushOrNull(finalized_block.ref())) |evicted_block| {
                    evicted_block.deinit(gpa);
                }

                _ = finalized_count.fetchAdd(finalized_block.num_transaction_ids, .Monotonic);

                log.info("finalized block {} (height {}, {} transaction(s))", .{
                    fmt.fmtSliceHexLower(&finalized_block.id),
                    finalized_block.height,
                    finalized_block.num_transaction_ids,
                });
            }
        }

        fn proposeBlock(
            self: *Self,
            ctx: *Context,
            gpa: mem.Allocator,
            transaction_ids: *std.ArrayListUnmanaged([32]u8),
        ) !void {
            if (self.pending.len == 0) {
                try runtime.timeout(ctx, .{ .nanoseconds = self.propose_delay });
                self.propose_delay = math.min(propose_delay_max, self.propose_delay + (propose_delay_max - propose_delay_min) / 10);
                return error.NoTransactionsToPropose;
            }

            self.propose_delay = propose_delay_min;

            defer transaction_ids.clearRetainingCapacity();

            for (self.pending.slice()) |entry| {
                if (!entry.isEmpty()) {
                    transaction_ids.appendAssumeCapacity(entry.value.id);
                    if (transaction_ids.items.len == Block.max_num_transaction_ids) {
                        break;
                    }
                }
            }

            const next_block_height = (if (self.blocks.latest()) |latest_block| latest_block.height else 0) + 1;

            const block = try Block.create(gpa, .{
                .height = next_block_height,
                .merkle_root = [_]u8{0} ** 32,
                .transaction_ids = transaction_ids.items,
            });

            self.sampler.prefer(gpa, block);

            log.debug("proposed block {} (height {}, {} transaction(s))", .{
                fmt.fmtSliceHexLower(&block.id),
                block.height,
                block.num_transaction_ids,
            });
        }

        fn pullBlockProposals(
            self: *Self,
            ctx: *Context,
            gpa: mem.Allocator,
            node: *Node,
            maybe_block_proposals: ?*BlockProposalMap,
            peer_ids: []const kademlia.ID,
            block_proposal_height: u64,
        ) !void {
            const frames = try gpa.alloc(@Frame(pullBlock), peer_ids.len);
            defer gpa.free(frames);

            var wg: sync.WaitGroup = .{};

            var frame_index: usize = 0;
            errdefer for (frames[0..frame_index]) |*frame| {
                _ = await frame catch continue;
            };

            while (frame_index < peer_ids.len) : (frame_index += 1) {
                frames[frame_index] = async self.pullBlock(ctx, gpa, &wg, node, peer_ids[frame_index].address, block_proposal_height);
            }

            try wg.wait(ctx);

            for (frames[0..frame_index]) |*frame| {
                const maybe_block_proposal = await frame catch null;
                const block_proposals = maybe_block_proposals orelse continue;

                const result = block_proposals.getOrPutAssumeCapacity(maybe_block_proposal);
                if (!result.found_existing) {
                    result.value_ptr.* = 0;
                }
                result.value_ptr.* += 1;
            }
        }

        fn pullBlock(
            self: *Self,
            ctx: *Context,
            gpa: mem.Allocator,
            wg: *sync.WaitGroup,
            node: *Node,
            address: ip.Address,
            block_height: u64,
        ) !*Block {
            wg.add(1);
            defer wg.sub(1);

            const client = try node.getOrCreateClient(ctx, gpa, address);

            const cached_block_proposal = if (self.block_proposal_cache.get(address)) |entry| entry.value.ref() else null;
            defer if (cached_block_proposal) |block_proposal| block_proposal.deinit(gpa);

            const cached_block_proposal_id = if (cached_block_proposal) |block_proposal| block_proposal.id else null;

            const block = client.pullBlock(ctx, gpa, block_height, cached_block_proposal_id, .{ .seconds = 5 }) catch |err| switch (err) {
                error.BlockPulledIsCached => {
                    const block_proposal = cached_block_proposal orelse return err;

                    // it is possible that our cached block proposal response may have
                    // been evicted by time we reach here, so an insertion may happen
                    // yet again

                    switch (self.block_proposal_cache.update(address, block_proposal.ref())) {
                        .inserted => {},
                        .updated => |old_block| old_block.deinit(gpa),
                        .evicted => |old_entry| old_entry.value.deinit(gpa),
                    }
                    return block_proposal;
                },
                else => return err,
            };
            errdefer block.deinit(gpa);

            if (block.height != block_height) {
                return error.UnexpectedPulledBlockHeight;
            }

            var conn = try self.store.acquireConnection();
            defer self.store.releaseConnection(&conn);

            var maybe_err: ?anyerror = null;

            var it = [_]u8{0} ** 32;
            for (block.transaction_ids[0..block.num_transaction_ids]) |tx_id| {
                if (!mem.lessThan(u8, &it, &tx_id)) {
                    maybe_err = error.BlockProposalTransactionIdsNotSorted;
                }
                if (node.chain.finalized.get(tx_id) != null or node.chain.store.isTransactionFinalized(&conn, tx_id)) {
                    if (maybe_err == null) {
                        maybe_err = error.TransactionAlreadyFinalized;
                    }
                    continue;
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
}

pub const TransactionPuller = struct {
    const log = std.log.scoped(.tx_puller);

    pub const max_num_bytes_per_batch = net.Packet.max_size - net.Packet.size;

    pub const collect_delay_min: i64 = 500 * time.ns_per_ms;
    pub const collect_delay_max: i64 = 1000 * time.ns_per_ms;

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

    pub fn run(self: *TransactionPuller, ctx: *Context, gpa: mem.Allocator) !void {
        var peer_ids: [16]kademlia.ID = undefined;

        while (true) {
            while (self.node.chain.missing.len == 0) {
                try runtime.timeout(ctx, .{ .nanoseconds = self.collect_delay });
                self.collect_delay = math.min(collect_delay_max, self.collect_delay * 2);
                continue;
            }

            self.collect_delay = collect_delay_min;

            // TODO: randomly sample peers from routing table instead
            const num_peers = self.node.table.closestTo(&peer_ids, self.node.id.public_key);
            while (num_peers == 0) {
                try runtime.timeout(ctx, .{ .nanoseconds = self.connected_delay });
                self.connected_delay = math.min(connected_delay_max, self.connected_delay + (connected_delay_max - connected_delay_min) / 10);
                continue;
            }

            self.connected_delay = connected_delay_min;

            self.pullMissingTransactions(ctx, gpa, peer_ids[0..num_peers]) catch |err| switch (err) {
                error.Cancelled => return,
                else => log.warn("error while pulling: {}", .{err}),
            };
        }
    }

    pub fn pullMissingTransactions(self: *TransactionPuller, ctx: *Context, gpa: mem.Allocator, peer_ids: []const kademlia.ID) !void {
        assert(self.node.chain.missing.len > 0);
        assert(peer_ids.len > 0);

        const ids = ids: {
            const total_num_ids = math.min(self.node.chain.missing.len, max_num_bytes_per_batch / @sizeOf([32]u8));

            var ids = try std.ArrayListUnmanaged([32]u8).initCapacity(gpa, total_num_ids);
            errdefer ids.deinit(gpa);

            var it = self.node.chain.missing.tail;
            while (it) |entry| : (it = self.node.chain.missing.tail) {
                ids.appendAssumeCapacity(entry.key);
                self.node.chain.missing.moveToFront(entry);
                if (ids.items.len == total_num_ids) {
                    break;
                }
            }

            break :ids ids.toOwnedSlice(gpa);
        };
        defer gpa.free(ids);

        const frames = try gpa.alloc(@Frame(pullTransactionsFromPeer), peer_ids.len);
        defer gpa.free(frames);

        var num_pulled_transactions: usize = 0;
        defer if (num_pulled_transactions >= 0) {
            log.info("pulled {}/{} missing transactions ({} total missing)", .{
                num_pulled_transactions,
                ids.len,
                num_pulled_transactions + self.node.chain.missing.len,
            });
        };

        var frame_index: usize = 0;
        defer for (frames[0..frame_index]) |*frame, i| {
            const transactions = await frame catch continue;
            defer gpa.free(transactions);

            for (transactions) |tx| {
                _ = self.node.chain.missing.delete(tx.id);

                if (self.node.pusher.isAlreadyGossipedToPeer(peer_ids[i].address, tx.id)) {
                    tx.deinit(gpa);
                    continue;
                }

                self.node.verifier.push(ctx, gpa, tx) catch {
                    tx.deinit(gpa);
                    continue;
                };

                num_pulled_transactions += 1;
            }
        };

        var wg: sync.WaitGroup = .{};
        while (frame_index < peer_ids.len) : (frame_index += 1) {
            frames[frame_index] = async self.pullTransactionsFromPeer(ctx, gpa, &wg, peer_ids[frame_index].address, ids);
        }
        try wg.wait(ctx);
    }

    pub fn pullTransactionsFromPeer(
        self: *TransactionPuller,
        ctx: *Context,
        gpa: mem.Allocator,
        wg: *sync.WaitGroup,
        address: ip.Address,
        ids: []const [32]u8,
    ) ![]const *Transaction {
        wg.add(1);
        defer wg.sub(1);

        const client = try self.node.getOrCreateClient(ctx, gpa, address);
        return client.pullTransactions(ctx, gpa, ids, .{ .seconds = 5 });
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
            return net.eqlIpAddress(a.address, b.address) and mem.eql(u8, &a.transaction_id, &b.transaction_id);
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

    num_bytes_pending: usize = 0,
    pending: std.ArrayListUnmanaged(*Transaction) = .{},
    pool: sync.BoundedTaskPool(gossipTransactions) = .{ .capacity = 128 },

    pub fn init(gpa: mem.Allocator, node: *Node) !TransactionPusher {
        var cache = try Cache.initCapacity(gpa, 1 << 20);
        errdefer cache.deinit(gpa);

        return TransactionPusher{ .node = node, .cache = cache };
    }

    pub fn deinit(self: *TransactionPusher, ctx: *Context, gpa: mem.Allocator) void {
        log.info("shutting down...", .{});

        self.pool.deinit(ctx, gpa) catch |err| log.warn("error while shutting down: {}", .{err});

        self.cache.deinit(gpa);

        for (self.pending.items) |tx| {
            tx.deinit(gpa);
        }
        self.pending.deinit(gpa);

        log.info("successfully shut down", .{});
    }

    pub fn push(self: *TransactionPusher, ctx: *Context, gpa: mem.Allocator, tx: *Transaction) !void {
        const tx_size = tx.size();
        if (self.num_bytes_pending + tx_size >= max_num_bytes_per_batch) {
            try self.flush(ctx, gpa);
        }

        try self.pending.append(gpa, tx);
        self.num_bytes_pending += tx_size;
    }

    pub fn run(self: *TransactionPusher, ctx: *Context, gpa: mem.Allocator) !void {
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

    pub fn flush(self: *TransactionPusher, ctx: *Context, gpa: mem.Allocator) !void {
        // TODO: randomly sample peer ids from routing table instead
        var peer_ids: [16]kademlia.ID = undefined;

        const num_peers = self.node.table.closestTo(&peer_ids, self.node.id.public_key);
        while (num_peers == 0) {
            try runtime.timeout(ctx, .{ .nanoseconds = self.connected_delay });
            self.connected_delay = math.min(connected_delay_max, self.connected_delay + (connected_delay_max - connected_delay_min) / 10);
        }

        self.connected_delay = connected_delay_min;

        try self.pool.spawn(ctx, gpa, .{ self, ctx, gpa, peer_ids[0..num_peers] });
    }

    pub fn isAlreadyGossipedToPeer(self: *TransactionPusher, address: ip.Address, transaction_id: [32]u8) bool {
        return self.cache.update(.{ .address = address, .transaction_id = transaction_id }, {}) == .updated;
    }

    fn gossipTransactions(self: *TransactionPusher, ctx: *Context, gpa: mem.Allocator, peer_ids: []const kademlia.ID) !void {
        const transactions = self.pending.toOwnedSlice(gpa);
        defer {
            for (transactions) |tx| {
                tx.deinit(gpa);
            }
            gpa.free(transactions);
        }

        self.num_bytes_pending = 0;

        const frames = try gpa.alloc(@Frame(TransactionPusher.pushTransactions), peer_ids.len);
        defer gpa.free(frames);

        var frame_index: usize = 0;
        defer for (frames[0..frame_index]) |*frame| await frame catch {};

        var wg: sync.WaitGroup = .{};
        defer wg.wait(ctx) catch {};

        while (frame_index < peer_ids.len) : (frame_index += 1) {
            var filtered_transactions: std.ArrayListUnmanaged(*Transaction) = .{};
            defer filtered_transactions.deinit(gpa);

            var filtered_transactions_len: u32 = 0;
            for (transactions) |tx| {
                if (self.isAlreadyGossipedToPeer(peer_ids[frame_index].address, tx.id)) {
                    continue;
                }

                try filtered_transactions.append(gpa, tx);
                filtered_transactions_len += tx.size();
            }

            frames[frame_index] = async self.pushTransactions(
                ctx,
                gpa,
                &wg,
                peer_ids[frame_index].address,
                filtered_transactions.toOwnedSlice(gpa),
                filtered_transactions_len,
            );
        }
    }

    fn pushTransactions(
        self: *TransactionPusher,
        ctx: *Context,
        gpa: mem.Allocator,
        wg: *sync.WaitGroup,
        address: ip.Address,
        transactions: []const *Transaction,
        transactions_len: u32,
    ) !void {
        wg.add(1);
        defer wg.sub(1);

        defer {
            _ = pusher_count.fetchAdd(transactions.len, .Monotonic);
            _ = pusher_bytes.fetchAdd(transactions_len, .Monotonic);
            gpa.free(transactions);
        }

        const client = try self.node.getOrCreateClient(ctx, gpa, address);
        try client.pushTransactions(ctx, gpa, transactions, .{ .seconds = 5 });
    }
};

pub const TransactionVerifier = struct {
    const log = std.log.scoped(.tx_verifier);

    pub const max_signature_batch_size = 64;
    pub const max_num_allowed_parallel_tasks = 128;

    pub const flush_delay_min: i64 = 100 * time.ns_per_ms;
    pub const flush_delay_max: i64 = 500 * time.ns_per_ms;

    node: *Node,

    pool: sync.BoundedTaskPool(verifyTransactions) = .{ .capacity = max_num_allowed_parallel_tasks },
    entries: std.ArrayListUnmanaged(*Transaction) = .{},
    last_flush_time: i64 = 0,

    pub fn init(node: *Node) TransactionVerifier {
        return TransactionVerifier{ .node = node };
    }

    pub fn deinit(self: *TransactionVerifier, ctx: *Context, gpa: mem.Allocator) void {
        log.info("shutting down...", .{});

        self.pool.deinit(ctx, gpa) catch |err| log.warn("error while shutting down: {}", .{err});

        for (self.entries.items) |tx| {
            tx.deinit(gpa);
        }
        self.entries.deinit(gpa);

        log.info("successfully shut down", .{});
    }

    pub fn push(self: *TransactionVerifier, ctx: *Context, gpa: mem.Allocator, tx: *Transaction) !void {
        try self.entries.append(gpa, tx);

        if (self.entries.items.len == max_signature_batch_size) {
            try self.flush(ctx, gpa);
        }
    }

    pub fn run(self: *TransactionVerifier, ctx: *Context, gpa: mem.Allocator) !void {
        var flush_delay: i64 = flush_delay_min;

        while (true) {
            if (self.entries.items.len == 0 or time.milliTimestamp() - self.last_flush_time < flush_delay_min / time.ns_per_ms) {
                try runtime.timeout(ctx, .{ .nanoseconds = flush_delay });
                flush_delay = math.min(flush_delay_max, flush_delay * 2);
                continue;
            }

            flush_delay = flush_delay_min;

            self.flush(ctx, gpa) catch |err| log.warn("error while flushing: {}", .{err});
        }
    }

    fn flush(self: *TransactionVerifier, ctx: *Context, gpa: mem.Allocator) !void {
        try self.pool.spawn(ctx, gpa, .{ self, ctx, gpa, self.entries.toOwnedSlice(gpa) });
        self.last_flush_time = time.milliTimestamp();
    }

    fn verifyTransactionBatch(gpa: mem.Allocator, entries: []*Transaction) usize {
        runtime.startCpuBoundOperation();
        defer runtime.endCpuBoundOperation();

        var num_valid: usize = 0;
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

                    entries[num_valid] = tx;
                    num_valid += 1;
                }

                continue;
            };

            mem.copy(*Transaction, entries[num_valid..], entries[num..][0..max_signature_batch_size]);
            num_valid += max_signature_batch_size;
        }

        for (entries[num..]) |tx| {
            crypto.verify(tx.signature, tx, tx.sender) catch |err| {
                log.warn("bad transaction {}: {}", .{ fmt.fmtSliceHexLower(&tx.id), err });
                tx.deinit(gpa);
                continue;
            };

            entries[num_valid] = tx;
            num_valid += 1;
        }

        return num_valid;
    }

    fn verifyTransactions(self: *TransactionVerifier, ctx: *Context, gpa: mem.Allocator, entries: []*Transaction) void {
        const num_valid = verifyTransactionBatch(gpa, entries);
        defer gpa.free(entries);

        self.node.chain.pending.ensureUnusedCapacity(gpa, num_valid) catch {
            for (entries[0..num_valid]) |tx| {
                tx.deinit(gpa);
            }
            return;
        };

        for (entries[0..num_valid]) |tx| {
            self.node.addTransaction(ctx, gpa, tx) catch {
                tx.deinit(gpa);
                continue;
            };
        }
    }
};

pub const Sampler = struct {
    const log = std.log.scoped(.sampler);

    pub const default_alpha = 0.8;
    pub const default_beta = 20;

    pub const Vote = struct {
        block: ?*Block,
        tally: f64,

        pub fn format(self: Vote, comptime layout: []const u8, options: fmt.FormatOptions, writer: anytype) !void {
            _ = layout;
            _ = options;
            try fmt.format(writer, "(block: {}, tally: {})", .{
                fmt.fmtSliceHexLower(if (self.block) |block| &block.id else &([_]u8{0} ** 32)),
                self.tally,
            });
        }
    };

    counts: SortedHashMap(usize, 50),
    count: usize = 0,
    stalled: usize = 0,
    preferred: ?*Block = null,
    last: ?*Block = null,

    pub fn init(gpa: mem.Allocator) !Sampler {
        var counts = try SortedHashMap(usize, 50).init(gpa);
        errdefer counts.deinit(gpa);

        return Sampler{ .counts = counts };
    }

    pub fn deinit(self: *Sampler, gpa: mem.Allocator) void {
        self.counts.deinit(gpa);
        if (self.preferred) |preferred| {
            preferred.deinit(gpa);
        }
        if (self.last) |last| {
            last.deinit(gpa);
        }
    }

    pub fn reset(self: *Sampler, gpa: mem.Allocator) void {
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

    pub fn prefer(self: *Sampler, gpa: mem.Allocator, block: *Block) void {
        if (self.preferred) |preferred| {
            preferred.deinit(gpa);
        }
        self.preferred = block;
    }

    pub fn update(self: *Sampler, gpa: mem.Allocator, votes: []const Vote) !?*Block {
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
            self.stalled = math.add(usize, self.stalled, 1) catch self.stalled;
            self.count = 0;
            return null;
        }

        self.stalled = 0;

        const count_result = self.counts.getOrPutAssumeCapacity(majority_block.id);
        if (!count_result.found_existing) count_result.value_ptr.* = 0;
        count_result.value_ptr.* += 1;

        const count = count_result.value_ptr.*;

        if (self.preferred) |preferred| {
            if (count > self.counts.get(preferred.id) orelse 0) {
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

const sqlite = @import("zig-sqlite/sqlite.zig");
const fs = std.fs;

pub const NullStore = struct {
    const PooledConnection = struct {};

    gpa: mem.Allocator,
    maybe_path: ?[]const u8,
    whitelist: AutoHashMap([32]u8, void, 50),

    pub fn init(gpa: mem.Allocator, maybe_path: ?[]const u8) !NullStore {
        var whitelist = try AutoHashMap([32]u8, void, 50).initCapacity(gpa, 16);
        errdefer whitelist.deinit(gpa);

        return NullStore{
            .gpa = gpa,
            .maybe_path = maybe_path,
            .whitelist = whitelist,
        };
    }

    pub fn deinit(self: *NullStore) void {
        self.whitelist.deinit(self.gpa);
    }

    pub fn acquireConnection(self: *NullStore) !PooledConnection {
        _ = self;
        return PooledConnection{};
    }

    pub fn releaseConnection(self: *NullStore, pooled: *PooledConnection) void {
        _ = self;
        _ = pooled;
    }

    pub fn queryJson(self: *NullStore, gpa: mem.Allocator, pooled: *PooledConnection, raw_query: []const u8) ![]const u8 {
        _ = self;
        _ = gpa;
        _ = pooled;
        _ = raw_query;
        return try gpa.dupe(u8, "{\"results\": [], \"count\": 0}");
    }

    pub fn storeBlock(self: *NullStore, gpa: mem.Allocator, pooled: *PooledConnection, block: *Block, transactions: []const *Transaction) !void {
        _ = self;
        _ = gpa;
        _ = pooled;
        _ = block;
        _ = transactions;
    }

    pub fn isTransactionFinalized(self: *NullStore, pooled: *PooledConnection, id: [32]u8) bool {
        _ = self;
        _ = pooled;
        _ = id;
        return false;
    }

    pub fn getBlockSummaries(self: *NullStore, gpa: mem.Allocator, pooled: *PooledConnection, offset: usize, limit: usize) ![]const Block.Summary {
        _ = self;
        _ = gpa;
        _ = pooled;
        _ = offset;
        _ = limit;
        return try gpa.alloc(Block.Summary, 0);
    }

    pub fn getBlocks(_: *NullStore, gpa: mem.Allocator, pooled: *PooledConnection, offset: usize, limit: usize) ![]const *Block {
        _ = gpa;
        _ = pooled;
        _ = offset;
        _ = limit;
        return try gpa.alloc(*Block, 0);
    }

    pub fn getTransactions(_: *NullStore, gpa: mem.Allocator, pooled: *PooledConnection, offset: usize, limit: usize) ![]const *Transaction {
        _ = gpa;
        _ = pooled;
        _ = offset;
        _ = limit;
        return try gpa.alloc(*Transaction, 0);
    }

    pub fn getTransactionsByBlockHeight(_: *NullStore, gpa: mem.Allocator, pooled: *PooledConnection, block_height: u64, offset: usize, limit: usize) ![]const *Transaction {
        _ = gpa;
        _ = pooled;
        _ = block_height;
        _ = offset;
        _ = limit;
        return try gpa.alloc(*Transaction, 0);
    }

    pub fn getBlockById(_: *NullStore, gpa: mem.Allocator, pooled: *PooledConnection, block_id: [32]u8) !?*Block {
        _ = gpa;
        _ = pooled;
        _ = block_id;
        return null;
    }

    pub fn getBlockByHeight(_: *NullStore, gpa: mem.Allocator, pooled: *PooledConnection, height: u64) !?*Block {
        _ = gpa;
        _ = pooled;
        _ = height;
        return null;
    }

    pub fn getTransactionById(_: *NullStore, gpa: mem.Allocator, pooled: *PooledConnection, id: [32]u8) !?*Transaction {
        _ = gpa;
        _ = pooled;
        _ = id;
        return null;
    }

    pub fn isPublicKeyWhitelisted(self: *NullStore, pooled: *PooledConnection, public_key: [32]u8) bool {
        _ = pooled;
        if (self.whitelist.len == 0) {
            return true;
        }
        return self.whitelist.get(public_key) != null;
    }

    pub fn addPublicKeyToWhitelist(self: *NullStore, pooled: *PooledConnection, public_key: [32]u8) !void {
        _ = pooled;
        return self.whitelist.put(self.gpa, public_key, {});
    }

    pub fn removePublicKeyFromWhitelist(self: *NullStore, pooled: *PooledConnection, public_key: [32]u8) bool {
        _ = pooled;
        return self.whitelist.delete(public_key) != null;
    }
};

pub const SqliteStore = struct {
    const store_block_query = "insert into blocks(id, height, merkle_root, num_transaction_ids) values (?{[]const u8}, ?{u64}, ?{[]const u8}, ?{u16})";
    const store_transaction_query = "insert into transactions(id, block_height, sender, signature, sender_nonce, created_at, tag, data) values (?{[]const u8}, ?{u64}, ?{[]const u8}, ?{[]const u8}, ?{u64}, ?{u64}, ?{[]const u8}, ?{[]const u8})";
    const is_transaction_finalized_query = "select 1 from transactions where id = ?{[]const u8}";
    const get_blocks_query = "select id, height, merkle_root from blocks order by height desc limit ?{usize} offset ?{usize}";
    const get_block_summaries_query = "select id, height, merkle_root, num_transaction_ids from blocks order by height desc limit ?{usize} offset ?{usize}";
    const get_block_by_id_query = "select height, merkle_root from blocks where id = ?{[]const u8}";
    const get_block_by_height_query = "select id, merkle_root from blocks where height = ?{u64}";
    const get_transactions_query = "select id, sender, signature, sender_nonce, created_at, tag, data from transactions order by block_height desc limit ?{usize} offset ?{usize}";
    const get_transaction_by_id_query = "select id, sender, signature, sender_nonce, created_at, tag, data from transactions where id = ?";
    const get_transaction_ids_by_block_height_query = "select id from transactions where block_height = ?{u64}";
    const get_transactions_by_block_height_query = "select id, sender, signature, sender_nonce, created_at, tag, data from transactions where block_height = ?{u64} limit ?{usize} offset ?{usize}";
    const is_whitelist_filled_query = "select 1 from whitelist";
    const is_public_key_whitelisted_query = "select 1 from whitelist where public_key = ?{[]const u8}";
    const add_public_key_to_whitelist_query = "insert or ignore into whitelist(public_key) values (?{[]const u8})";
    const remove_public_key_from_whitelist_query = "delete from whitelist where public_key = ?{[]const u8}";

    pub const PooledConnection = struct {
        conn: sqlite.Db,

        store_block: sqlite.Statement(.{}, sqlite.ParsedQuery.from(store_block_query)),
        store_transaction: sqlite.Statement(.{}, sqlite.ParsedQuery.from(store_transaction_query)),
        is_transaction_finalized: sqlite.Statement(.{}, sqlite.ParsedQuery.from(is_transaction_finalized_query)),
        get_blocks: sqlite.Statement(.{}, sqlite.ParsedQuery.from(get_blocks_query)),
        get_block_summaries: sqlite.Statement(.{}, sqlite.ParsedQuery.from(get_block_summaries_query)),
        get_block_by_id: sqlite.Statement(.{}, sqlite.ParsedQuery.from(get_block_by_id_query)),
        get_block_by_height: sqlite.Statement(.{}, sqlite.ParsedQuery.from(get_block_by_height_query)),
        get_transactions: sqlite.Statement(.{}, sqlite.ParsedQuery.from(get_transactions_query)),
        get_transaction_by_id: sqlite.Statement(.{}, sqlite.ParsedQuery.from(get_transaction_by_id_query)),
        get_transaction_ids_by_block_height: sqlite.Statement(.{}, sqlite.ParsedQuery.from(get_transaction_ids_by_block_height_query)),
        get_transactions_by_block_height: sqlite.Statement(.{}, sqlite.ParsedQuery.from(get_transactions_by_block_height_query)),
        is_whitelist_filled: sqlite.Statement(.{}, sqlite.ParsedQuery.from(is_whitelist_filled_query)),
        is_public_key_whitelisted: sqlite.Statement(.{}, sqlite.ParsedQuery.from(is_public_key_whitelisted_query)),
        add_public_key_to_whitelist: sqlite.Statement(.{}, sqlite.ParsedQuery.from(add_public_key_to_whitelist_query)),
        remove_public_key_from_whitelist: sqlite.Statement(.{}, sqlite.ParsedQuery.from(remove_public_key_from_whitelist_query)),

        pub fn deinit(self: *PooledConnection) void {
            self.store_block.deinit();
            self.store_transaction.deinit();
            self.is_transaction_finalized.deinit();
            self.get_blocks.deinit();
            self.get_block_summaries.deinit();
            self.get_block_by_id.deinit();
            self.get_block_by_height.deinit();
            self.get_transactions.deinit();
            self.get_transaction_by_id.deinit();
            self.get_transaction_ids_by_block_height.deinit();
            self.get_transactions_by_block_height.deinit();
            self.is_whitelist_filled.deinit();
            self.is_public_key_whitelisted.deinit();
            self.add_public_key_to_whitelist.deinit();
            self.remove_public_key_from_whitelist.deinit();
            self.conn.deinit();
        }
    };

    const log = std.log.scoped(.sqlite);

    pool: std.fifo.LinearFifo(PooledConnection, .Dynamic),
    maybe_path: ?[]const u8,

    pub fn init(gpa: mem.Allocator, maybe_path: ?[]const u8) !SqliteStore {
        var pooled = try createConnection(maybe_path);
        errdefer pooled.deinit();

        var pool = std.fifo.LinearFifo(PooledConnection, .Dynamic).init(gpa);
        errdefer pool.deinit();

        try pool.writeItem(pooled);

        return SqliteStore{ .pool = pool, .maybe_path = maybe_path };
    }

    pub fn deinit(self: *SqliteStore) void {
        while (self.pool.readItem()) |pooled_const| {
            var pooled = pooled_const;
            pooled.deinit();
        }
        self.pool.deinit();
    }

    fn createConnection(maybe_path: ?[]const u8) !PooledConnection {
        var diags: sqlite.Diagnostics = .{};
        errdefer |err| log.warn("failed to create sqlite connection to '{s}' ({}): {}", .{ maybe_path, err, diags });

        var conn: sqlite.Db = db: {
            const path = maybe_path orelse {
                break :db try sqlite.Db.init(.{
                    .mode = .{ .File = "file:rheia?mode=memory&cache=shared" },
                    .open_flags = .{ .create = true, .write = true },
                    .threading_mode = .MultiThread,
                    .shared_cache = true,
                    .diags = &diags,
                });
            };

            var path_buf: [fs.MAX_PATH_BYTES]u8 = undefined;
            mem.copy(u8, &path_buf, path);
            path_buf[path.len] = 0;

            break :db try sqlite.Db.init(.{
                .mode = .{ .File = path_buf[0..path.len :0] },
                .open_flags = .{ .create = true, .write = true },
                .threading_mode = .MultiThread,
                .shared_cache = true,
                .diags = &diags,
            });
        };
        errdefer conn.deinit();

        var error_message: [*c]u8 = null;
        defer if (error_message) |error_message_ptr| {
            log.warn("failed to init schema: {s}", .{error_message_ptr});
            sqlite.c.sqlite3_free(error_message_ptr);
        };

        if (sqlite.c.sqlite3_exec(conn.db, @embedFile("schema.sql"), null, null, &error_message) != sqlite.c.SQLITE_OK) {
            return error.SQLiteError;
        }

        const Authorizer = struct {
            pub fn check(
                user_data: ?*anyopaque,
                action_code: c_int,
                param_1: ?[*:0]const u8,
                param_2: ?[*:0]const u8,
                param_3: ?[*:0]const u8,
                param_4: ?[*:0]const u8,
            ) callconv(.C) c_int {
                _ = user_data;
                _ = param_2;
                _ = param_3;
                _ = param_4;

                switch (action_code) {
                    sqlite.c.SQLITE_DELETE => {
                        const table_name = mem.sliceTo(param_1 orelse return sqlite.c.SQLITE_OK, 0);
                        if (mem.eql(u8, table_name, "blocks") or
                            mem.eql(u8, table_name, "transactions"))
                        {
                            return sqlite.c.SQLITE_DENY;
                        }
                    },
                    sqlite.c.SQLITE_UPDATE,
                    sqlite.c.SQLITE_DROP_TABLE,
                    => {
                        const table_name = mem.sliceTo(param_1 orelse return sqlite.c.SQLITE_OK, 0);
                        if (mem.eql(u8, table_name, "blocks") or
                            mem.eql(u8, table_name, "transactions") or
                            mem.eql(u8, table_name, "whitelist"))
                        {
                            return sqlite.c.SQLITE_DENY;
                        }
                    },
                    else => {},
                }

                return sqlite.c.SQLITE_OK;
            }
        };

        _ = try conn.pragma(void, .{}, "page_size", "32768");
        _ = try conn.pragma(void, .{}, "journal_mode", "WAL");
        _ = try conn.pragma(void, .{}, "read_uncommitted", "true");
        _ = try conn.pragma(void, .{}, "synchronous", "off");
        _ = try conn.pragma(void, .{}, "temp_store", "memory");
        _ = try conn.pragma(void, .{}, "mmap_size", "30000000000");

        var pooled: PooledConnection = undefined;

        pooled.conn = conn;

        pooled.store_block = try pooled.conn.prepareWithDiags(store_block_query, .{ .diags = &diags });
        errdefer pooled.store_block.deinit();

        pooled.store_transaction = try pooled.conn.prepareWithDiags(store_transaction_query, .{ .diags = &diags });
        errdefer pooled.store_transaction.deinit();

        pooled.is_transaction_finalized = try pooled.conn.prepareWithDiags(is_transaction_finalized_query, .{ .diags = &diags });
        errdefer pooled.is_transaction_finalized.deinit();

        pooled.get_blocks = try pooled.conn.prepareWithDiags(get_blocks_query, .{ .diags = &diags });
        errdefer pooled.get_blocks.deinit();

        pooled.get_block_summaries = try pooled.conn.prepareWithDiags(get_block_summaries_query, .{ .diags = &diags });
        errdefer pooled.get_block_summaries.deinit();

        pooled.get_block_by_id = try pooled.conn.prepareWithDiags(get_block_by_id_query, .{ .diags = &diags });
        errdefer pooled.get_block_by_id.deinit();

        pooled.get_block_by_height = try pooled.conn.prepareWithDiags(get_block_by_height_query, .{ .diags = &diags });
        errdefer pooled.get_block_by_height.deinit();

        pooled.get_transactions = try pooled.conn.prepareWithDiags(get_transactions_query, .{ .diags = &diags });
        errdefer pooled.get_transactions.deinit();

        pooled.get_transaction_by_id = try pooled.conn.prepareWithDiags(get_transaction_by_id_query, .{ .diags = &diags });
        errdefer pooled.get_transaction_by_id.deinit();

        pooled.get_transaction_ids_by_block_height = try pooled.conn.prepareWithDiags(get_transaction_ids_by_block_height_query, .{ .diags = &diags });
        errdefer pooled.get_transaction_ids_by_block_height.deinit();

        pooled.get_transactions_by_block_height = try pooled.conn.prepareWithDiags(get_transactions_by_block_height_query, .{ .diags = &diags });
        errdefer pooled.get_transactions_by_block_height.deinit();

        pooled.is_whitelist_filled = try pooled.conn.prepareWithDiags(is_whitelist_filled_query, .{ .diags = &diags });
        errdefer pooled.is_whitelist_filled.deinit();

        pooled.is_public_key_whitelisted = try pooled.conn.prepareWithDiags(is_public_key_whitelisted_query, .{ .diags = &diags });
        errdefer pooled.is_public_key_whitelisted.deinit();

        pooled.add_public_key_to_whitelist = try pooled.conn.prepareWithDiags(add_public_key_to_whitelist_query, .{ .diags = &diags });
        errdefer pooled.add_public_key_to_whitelist.deinit();

        pooled.remove_public_key_from_whitelist = try pooled.conn.prepareWithDiags(remove_public_key_from_whitelist_query, .{ .diags = &diags });
        errdefer pooled.remove_public_key_from_whitelist.deinit();

        if (sqlite.c.sqlite3_set_authorizer(conn.db, Authorizer.check, null) != sqlite.c.SQLITE_OK) {
            return error.AuthorizerNotInitialized;
        }

        return pooled;
    }

    pub fn acquireConnection(self: *SqliteStore) !PooledConnection {
        if (self.pool.readItem()) |conn| {
            return conn;
        }
        return try createConnection(self.maybe_path);
    }

    pub fn releaseConnection(self: *SqliteStore, pooled: *PooledConnection) void {
        // Silently fail.
        self.pool.writeItem(pooled.*) catch pooled.deinit();
    }

    fn execute(gpa: mem.Allocator, pooled: *PooledConnection, raw_query: []const u8) !void {
        var error_message: [*c]u8 = null;
        defer if (error_message) |error_message_ptr| {
            log.warn("error while executing query: {s}", .{error_message_ptr});
            sqlite.c.sqlite3_free(error_message_ptr);
        };

        const query = try std.cstr.addNullByte(gpa, raw_query);
        defer gpa.free(query);

        if (sqlite.c.sqlite3_exec(pooled.conn.db, query.ptr, null, null, &error_message) != sqlite.c.SQLITE_OK) {
            return error.SQLiteError;
        }
    }

    pub fn queryJson(_: *SqliteStore, gpa: mem.Allocator, pooled: *PooledConnection, raw_query: []const u8) ![]const u8 {
        var diags: sqlite.Diagnostics = .{};
        errdefer |err| log.warn("error while querying json ({}): {}", .{ diags, err });

        var buffer = std.ArrayList(u8).init(gpa);
        defer buffer.deinit();

        var stream = std.json.writeStream(buffer.writer(), 128);

        var stmt: ?*sqlite.c.sqlite3_stmt = undefined;
        var result = sqlite.c.sqlite3_prepare_v3(
            pooled.conn.db,
            raw_query.ptr,
            @intCast(c_int, raw_query.len),
            0,
            &stmt,
            null,
        );
        if (result != sqlite.c.SQLITE_OK) {
            diags.err = pooled.conn.getDetailedError();
            return sqlite.errors.errorFromResultCode(result);
        }
        defer _ = sqlite.c.sqlite3_finalize(stmt);

        if (sqlite.c.sqlite3_stmt_readonly(stmt) == 0) {
            return error.QueryNotReadOnly;
        }

        var count: usize = 0;

        try stream.beginObject();

        try stream.objectField("results");
        try stream.beginArray();

        while (true) {
            result = sqlite.c.sqlite3_step(stmt);
            switch (result) {
                sqlite.c.SQLITE_DONE => break,
                sqlite.c.SQLITE_ROW => {},
                else => {
                    diags.err = pooled.conn.getDetailedError();
                    return sqlite.errors.errorFromResultCode(result);
                },
            }

            try stream.arrayElem();
            try stream.beginObject();

            var i: c_int = 0;
            while (i < sqlite.c.sqlite3_column_count(stmt)) : (i += 1) {
                const column_name = sqlite.c.sqlite3_column_name(stmt, i) orelse return error.OutOfMemory;
                try stream.objectField(mem.sliceTo(column_name, 0));
                switch (sqlite.c.sqlite3_column_type(stmt, i)) {
                    sqlite.c.SQLITE_INTEGER => {
                        try stream.emitNumber(sqlite.c.sqlite3_column_int64(stmt, i));
                    },
                    sqlite.c.SQLITE_FLOAT => {
                        try stream.emitNumber(sqlite.c.sqlite3_column_double(stmt, i));
                    },
                    sqlite.c.SQLITE_TEXT => {
                        const num_bytes = @intCast(usize, sqlite.c.sqlite3_column_bytes(stmt, i));
                        try stream.emitJson(.{ .String = sqlite.c.sqlite3_column_text(stmt, i)[0..num_bytes] });
                    },
                    sqlite.c.SQLITE_BLOB => {
                        const num_bytes = @intCast(usize, sqlite.c.sqlite3_column_bytes(stmt, i));
                        try stream.emitJson(.{ .String = sqlite.c.sqlite3_column_text(stmt, i)[0..num_bytes] });
                    },
                    sqlite.c.SQLITE_NULL => {
                        try stream.emitNull();
                    },
                    else => unreachable,
                }
            }

            try stream.endObject();

            count += 1;

            if (buffer.items.len > 1 * 1024 * 1024) {
                break;
            }
        }

        try stream.endArray();

        try stream.objectField("count");
        try stream.emitNumber(count);

        try stream.endObject();

        return buffer.toOwnedSlice();
    }

    pub fn storeBlock(_: *SqliteStore, gpa: mem.Allocator, pooled: *PooledConnection, block: *Block, transactions: []const *Transaction) !void {
        var diags: sqlite.Diagnostics = .{};
        errdefer |err| log.warn("error while saving block ({}): {}", .{ diags, err });

        try pooled.conn.exec("begin", .{ .diags = &diags }, .{});
        errdefer pooled.conn.exec("rollback", .{ .diags = &diags }, .{}) catch {};

        pooled.store_block.reset();

        try pooled.store_block.exec(.{ .diags = &diags }, .{
            .id = @as([]const u8, &block.id),
            .height = block.height,
            .merkle_root = @as([]const u8, &block.merkle_root),
            .num_transaction_ids = block.num_transaction_ids,
        });

        for (transactions) |tx| {
            pooled.store_transaction.reset();

            try pooled.store_transaction.exec(
                .{ .diags = &diags },
                .{
                    .id = @as([]const u8, &tx.id),
                    .block_height = block.height,
                    .sender = @as([]const u8, &tx.sender),
                    .signature = @as([]const u8, &tx.signature),
                    .sender_nonce = tx.sender_nonce,
                    .created_at = tx.created_at,
                    .tag = tx.tag,
                    .data = @as([]const u8, tx.data[0..tx.data_len]),
                },
            );

            switch (tx.tag) {
                .no_op => {},
                .stmt => execute(gpa, pooled, tx.data[0..tx.data_len]) catch {},
            }
        }

        try pooled.conn.exec("commit", .{ .diags = &diags }, .{});
    }

    pub fn isTransactionFinalized(_: *SqliteStore, pooled: *PooledConnection, id: [32]u8) bool {
        var diags: sqlite.Diagnostics = .{};
        errdefer log.warn("error while checking if transaction is finalized: {}", .{diags});

        pooled.is_transaction_finalized.reset();

        const result = pooled.is_transaction_finalized.one(usize, .{ .diags = &diags }, .{ .id = @as([]const u8, &id) }) catch return false;
        return result != null;
    }

    fn getTransactionIdsByBlockHeight(gpa: mem.Allocator, pooled: *PooledConnection, block_height: u64) ![]const [32]u8 {
        pooled.get_transaction_ids_by_block_height.reset();
        return try pooled.get_transaction_ids_by_block_height.all([32]u8, gpa, .{}, .{ .block_height = block_height });
    }

    pub fn getBlockSummaries(_: *SqliteStore, gpa: mem.Allocator, pooled: *PooledConnection, offset: usize, limit: usize) ![]const Block.Summary {
        var blocks: std.ArrayListUnmanaged(Block.Summary) = .{};
        defer blocks.deinit(gpa);

        var diags: sqlite.Diagnostics = .{};
        errdefer |err| log.warn("error while fetching block summaries ({}): {}", .{ diags, err });

        pooled.get_block_summaries.reset();

        var it = try pooled.get_block_summaries.iterator(Block.Summary, .{ limit, offset });
        while (try it.next(.{ .diags = &diags })) |summary| {
            try blocks.append(gpa, summary);
        }

        return blocks.toOwnedSlice(gpa);
    }

    pub fn getBlocks(_: *SqliteStore, gpa: mem.Allocator, pooled: *PooledConnection, offset: usize, limit: usize) ![]const *Block {
        var blocks: std.ArrayListUnmanaged(*Block) = .{};
        defer {
            for (blocks.items) |block| {
                block.deinit(gpa);
            }
            blocks.deinit(gpa);
        }

        var diags: sqlite.Diagnostics = .{};
        errdefer |err| log.warn("error while fetching blocks ({}): {}", .{ diags, err });

        pooled.get_blocks.reset();

        var it = try pooled.get_blocks.iterator(struct { id: [32]u8, height: u64, merkle_root: [32]u8 }, .{ limit, offset });
        while (try it.next(.{ .diags = &diags })) |header| {
            const transaction_ids = try getTransactionIdsByBlockHeight(gpa, pooled, header.height);
            defer gpa.free(transaction_ids);

            const block = try Block.from(gpa, .{
                .id = header.id,
                .height = header.height,
                .merkle_root = header.merkle_root,
                .transaction_ids = transaction_ids,
            });
            errdefer block.deinit(gpa);

            try blocks.append(gpa, block);
        }

        return blocks.toOwnedSlice(gpa);
    }

    pub fn getTransactions(_: *SqliteStore, gpa: mem.Allocator, pooled: *PooledConnection, offset: usize, limit: usize) ![]const *Transaction {
        var transactions: std.ArrayListUnmanaged(*Transaction) = .{};
        defer {
            for (transactions.items) |tx| {
                tx.deinit(gpa);
            }
            transactions.deinit(gpa);
        }

        var diags: sqlite.Diagnostics = .{};
        errdefer |err| log.warn("error while fetching transactions ({}): {}", .{ diags, err });

        pooled.get_transactions.reset();

        var it = try pooled.get_transactions.iterator(Transaction.Data, .{ limit, offset });
        while (try it.nextAlloc(gpa, .{ .diags = &diags })) |format| {
            defer gpa.free(format.data);

            const tx = try Transaction.from(gpa, format);
            errdefer tx.deinit(gpa);

            try transactions.append(gpa, tx);
        }

        return transactions.toOwnedSlice(gpa);
    }

    pub fn getTransactionsByBlockHeight(_: *SqliteStore, gpa: mem.Allocator, pooled: *PooledConnection, block_height: u64, offset: usize, limit: usize) ![]const *Transaction {
        var transactions: std.ArrayListUnmanaged(*Transaction) = .{};
        defer {
            for (transactions.items) |tx| {
                tx.deinit(gpa);
            }
            transactions.deinit(gpa);
        }

        var diags: sqlite.Diagnostics = .{};
        errdefer |err| log.warn("error while fetching transactions ({}): {}", .{ diags, err });

        pooled.get_transactions_by_block_height.reset();

        var it = try pooled.get_transactions_by_block_height.iterator(Transaction.Data, .{ block_height, limit, offset });
        while (try it.nextAlloc(gpa, .{ .diags = &diags })) |format| {
            defer gpa.free(format.data);

            const tx = try Transaction.from(gpa, format);
            errdefer tx.deinit(gpa);

            try transactions.append(gpa, tx);
        }

        return transactions.toOwnedSlice(gpa);
    }

    pub fn getBlockById(_: *SqliteStore, gpa: mem.Allocator, pooled: *PooledConnection, block_id: [32]u8) !?*Block {
        var diags: sqlite.Diagnostics = .{};
        errdefer |err| log.warn("error while fetching block by id ({}): {}", .{ diags, err });

        pooled.get_block_by_id.reset();

        const header = (try pooled.get_block_by_id.one(struct {
            height: u64,
            merkle_root: [32]u8,
        }, .{ .diags = &diags }, .{ .id = @as([]const u8, &block_id) })) orelse return null;

        const transaction_ids = try getTransactionIdsByBlockHeight(gpa, pooled, header.height);
        defer gpa.free(transaction_ids);

        return try Block.from(gpa, .{
            .id = block_id,
            .height = header.height,
            .merkle_root = header.merkle_root,
            .transaction_ids = transaction_ids,
        });
    }

    pub fn getBlockByHeight(_: *SqliteStore, gpa: mem.Allocator, pooled: *PooledConnection, height: u64) !?*Block {
        var diags: sqlite.Diagnostics = .{};
        errdefer |err| log.warn("error while fetching block by height ({}): {}", .{ diags, err });

        pooled.get_block_by_height.reset();

        const header = (try pooled.get_block_by_height.one(struct {
            id: [32]u8,
            merkle_root: [32]u8,
        }, .{ .diags = &diags }, .{ .height = height })) orelse return null;

        const transaction_ids = try getTransactionIdsByBlockHeight(gpa, pooled, height);
        defer gpa.free(transaction_ids);

        return try Block.from(gpa, .{
            .id = header.id,
            .height = height,
            .merkle_root = header.merkle_root,
            .transaction_ids = transaction_ids,
        });
    }

    pub fn getTransactionById(_: *SqliteStore, gpa: mem.Allocator, pooled: *PooledConnection, id: [32]u8) !?*Transaction {
        var diags: sqlite.Diagnostics = .{};
        errdefer |err| log.warn("error while fetching transaction by id ({}): {}", .{ diags, err });

        pooled.get_transaction_by_id.reset();

        const format = (try pooled.get_transaction_by_id.oneAlloc(Transaction.Data, gpa, .{ .diags = &diags }, .{ .id = @as([]const u8, &id) })) orelse return null;
        defer gpa.free(format.data);

        return try Transaction.from(gpa, format);
    }

    pub fn isPublicKeyWhitelisted(_: *SqliteStore, pooled: *PooledConnection, public_key: [32]u8) bool {
        var diags: sqlite.Diagnostics = .{};
        errdefer log.warn("error while checking if public key is whitelisted: {}", .{diags});

        pooled.is_whitelist_filled.reset();

        if ((pooled.is_whitelist_filled.one(usize, .{ .diags = &diags }, .{}) catch return false) == null) {
            return true;
        }

        pooled.is_public_key_whitelisted.reset();

        if ((pooled.is_public_key_whitelisted.one(usize, .{ .diags = &diags }, .{ .public_key = @as([]const u8, &public_key) }) catch return false) != null) {
            return true;
        }

        return false;
    }

    pub fn addPublicKeyToWhitelist(_: *SqliteStore, pooled: *PooledConnection, public_key: [32]u8) !void {
        var diags: sqlite.Diagnostics = .{};
        errdefer log.warn("error while adding public key to whitelist: {}", .{diags});

        pooled.add_public_key_to_whitelist.reset();

        try pooled.add_public_key_to_whitelist.exec(
            .{ .diags = &diags },
            .{ .public_key = @as([]const u8, &public_key) },
        );
    }

    pub fn removePublicKeyFromWhitelist(_: *SqliteStore, pooled: *PooledConnection, public_key: [32]u8) bool {
        var diags: sqlite.Diagnostics = .{};
        errdefer log.warn("error while removing public key from whitelist: {}", .{diags});

        pooled.remove_public_key_from_whitelist.reset();

        pooled.remove_public_key_from_whitelist.exec(
            .{ .diags = &diags },
            .{ .public_key = @as([]const u8, &public_key) },
        ) catch return false;

        if (pooled.conn.rowsAffected() == 0) {
            return false;
        }

        return true;
    }
};
