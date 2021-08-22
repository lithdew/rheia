const std = @import("std");
const net = @import("net.zig");
const rheia = @import("main.zig");
const runtime = @import("runtime.zig");

const io = std.io;
const os = std.os;
const ip = std.x.net.ip;
const mem = std.mem;
const fmt = std.fmt;
const time = std.time;

const IPv4 = std.x.os.IPv4;
const Atomic = std.atomic.Atomic;
const Context = runtime.Context;
const Ed25519 = std.crypto.sign.Ed25519;

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

    var ctx: Context = .{};
    defer ctx.cancel();

    const keys = try Ed25519.KeyPair.create(null);
    log.debug("public key: {}", .{fmt.fmtSliceHexLower(&keys.public_key)});
    log.debug("secret key: {}", .{fmt.fmtSliceHexLower(keys.secret_key[0..Ed25519.seed_length])});

    var stats_frame = async reportBenchmarkStats(&ctx);
    defer await stats_frame catch |err| log.warn("stats error: {}", .{err});

    var frames = try runtime.getAllocator().alloc(@Frame(runBenchmark), 16);
    defer runtime.getAllocator().free(frames);

    var frame_index: usize = 0;
    defer for (frames[0..frame_index]) |*frame| {
        await frame catch |err| switch (err) {
            error.Closed, error.Cancelled => {},
            else => log.warn("error: {}", .{err}),
        };
    };

    const client_address = ip.Address.initIPv4(IPv4.localhost, 9000);
    log.info("sending transactions to {}...", .{client_address});

    var client = try rheia.Client.init(runtime.getAllocator(), client_address);
    defer {
        var shutdown_ctx: Context = .{};
        defer shutdown_ctx.cancel();

        if (client.deinit(&shutdown_ctx, runtime.getAllocator())) |_| {
            log.info("client successfully shut down", .{});
        } else |err| {
            log.warn("client reported an error while shutting down: {}", .{err});
        }
    }

    while (frame_index < frames.len) : (frame_index += 1) {
        frames[frame_index] = async runBenchmark(&ctx, keys, &client);
    }

    runtime.waitForSignal(&ctx, .{os.SIGINT}) catch {};
    log.info("gracefully shutting down...", .{});

    ctx.cancel();
}

var benchmark_count: Atomic(u64) = .{ .value = 0 };
var nonce_count: Atomic(u64) = .{ .value = 0 };

pub fn reportBenchmarkStats(ctx: *Context) !void {
    const log = std.log.scoped(.benchmark);

    while (true) {
        try runtime.timeout(ctx, .{ .nanoseconds = 1 * time.ns_per_s });
        log.info("created and sent {} transaction(s)", .{benchmark_count.swap(0, .Monotonic)});
    }
}

pub fn runBenchmark(ctx: *Context, keys: Ed25519.KeyPair, client: *rheia.Client) !void {
    while (true) {
        const nonce = nonce_count.fetchAdd(1, .Monotonic);

        const tx = try tx: {
            runtime.startCpuBoundOperation();
            defer runtime.endCpuBoundOperation();

            break :tx rheia.Transaction.create(runtime.getAllocator(), keys, .{
                .sender_nonce = nonce,
                .created_at = nonce,
                .tag = .no_op,
                .data = "hello world",
            });
        };
        defer tx.deinit(runtime.getAllocator());

        try await async sendTransactions(ctx, client, &[_]*rheia.Transaction{tx});

        _ = benchmark_count.fetchAdd(1, .Monotonic);
    }
}

pub fn sendTransactions(ctx: *Context, client: *rheia.Client, transactions: []const *rheia.Transaction) !void {
    var len: u32 = 0;
    for (transactions) |tx| {
        len += tx.size();
    }

    const writer = try client.acquireWriter(ctx, runtime.getAllocator());
    defer client.releaseWriter(writer);

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
