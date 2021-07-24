const std = @import("std");

const os = std.os;
const mem = std.mem;

const ip = std.x.net.ip;
const tcp = std.x.net.tcp;
const log = std.log.scoped(.rheia);

const assert = std.debug.assert;

const IPv4 = std.x.os.IPv4;

const Server = @import("Server.zig");
const Client = @import("Client.zig");
const runtime = @import("runtime.zig");

const binary = @import("binary.zig");
const Packet = @import("Packet.zig");

pub const log_level = .debug;

pub fn main() !void {
    defer log.info("shutdown successful", .{});

    try runtime.init();
    defer {
        runtime.join();
        runtime.deinit();
    }
    try runtime.start();

    var frame = async run();
    try runtime.run();
    try nosuspend await frame;
}

pub fn run() !void {
    defer runtime.shutdown();

    // var server = Server.init();
    // defer {
    //     server.shutdown();
    //     server.join();
    //     server.deinit(runtime.getAllocator());
    // }

    // var listener = try tcp.Listener.init(.ip, .{ .close_on_exec = true });
    // defer listener.deinit();

    // try listener.setReuseAddress(true);
    // try listener.setFastOpen(true);

    // try listener.bind(ip.Address.initIPv4(IPv4.localhost, 9000));
    // try listener.listen(128);

    // var listener_frame = async server.serve(runtime.getAllocator(), listener);
    // defer {
    //     listener.shutdown() catch |err| log.warn("listener shutdown error: {}", .{err});
    //     await listener_frame catch |err| log.warn("listener error: {}", .{err});
    // }

    var client = try Client.init(runtime.getAllocator(), ip.Address.initIPv4(IPv4.localhost, 9000));
    defer {
        client.join();
        client.deinit(runtime.getAllocator());
    }

    var client_timer: runtime.Request = .{};
    var client_frame = async runClient(&client_timer, &client);
    defer {
        runtime.cancel(&client_timer);
        client.shutdown();
        await client_frame catch |err| log.warn("client error: {}", .{err});
    }

    try runtime.waitForSignal();

    log.info("gracefully shutting down...", .{});
}

fn runClient(_: *runtime.Request, client: *Client) !void {
    // log.info("starting benchmark in 3...", .{});
    // try runtime.timeout(client_timer, .{ .seconds = 1 });
    // log.info("starting benchmark in 2...", .{});
    // try runtime.timeout(client_timer, .{ .seconds = 1 });
    // log.info("starting benchmark in 1...", .{});
    // try runtime.timeout(client_timer, .{ .seconds = 1 });

    var timer = try std.time.Timer.start();
    var packets_per_second: usize = 0;
    var last_print_time: usize = 0;

    var i: u32 = 0;
    while (i < 100_000_000) : (i += 1) {
        // var waiter: Client.RPC.Waiter = .{
        //     .worker_id = runtime.getCurrentWorkerId(),
        //     .task = .{ .frame = @frame() },
        // };
        // const nonce = try client.rpc.park(&waiter);
        // errdefer _ = client.rpc.cancel(nonce);

        const nonce = i;

        var buf = std.ArrayList(u8).init(runtime.getAllocator());
        defer buf.deinit();

        var size_data = try binary.allocate(binary.Buffer.from(&buf), u32);
        var body_data = try Packet.append(size_data.sliceFromEnd(), .{ .nonce = nonce, .@"type" = .request, .tag = .ping });
        size_data = binary.writeAssumeCapacity(size_data.sliceFromStart(), @intCast(u32, size_data.len + body_data.len));

        try await async client.write(runtime.getAllocator(), buf.items);

        packets_per_second += 1;

        const current_time = timer.read();

        if (current_time - last_print_time > 1 * std.time.ns_per_s) {
            log.info("spammed {} ping packets in the last second", .{packets_per_second});

            last_print_time = current_time;
            packets_per_second = 0;
        }
    }

    log.info("done! took {}", .{std.fmt.fmtDuration(timer.read())});
}
