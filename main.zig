const std = @import("std");

const mem = std.mem;

const ip = std.x.net.ip;
const tcp = std.x.net.tcp;
const log = std.log.scoped(.rheia);

const assert = std.debug.assert;

const IPv4 = std.x.os.IPv4;
const Socket = std.x.os.Socket;

const Loop = @import("io.zig").Loop;

pub const Worker = struct {
    loop: Loop,

    pub fn init(self: *Worker) !void {
        try self.loop.init(null);
        errdefer self.loop.deinit();
    }

    pub fn deinit(self: *Worker) void {
        self.loop.deinit();
    }

    pub fn run(self: *Worker) !void {
        try self.loop.run();
    }
};

pub fn main() !void {
    // general-purpose memory allocator

    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer assert(!gpa.deinit());

    const allocator = &gpa.allocator;

    // i/o workers

    const worker_count = try std.Thread.getCpuCount();
    if (worker_count <= 1) return error.SingleThreaded;

    var workers = try std.ArrayListUnmanaged(Worker).initCapacity(allocator, worker_count);
    defer {
        for (workers.items) |*worker| worker.deinit();
        workers.deinit(allocator);
    }
    for (workers.items.ptr[0..worker_count]) |_| {
        try workers.addOneAssumeCapacity().init();
    }

    // i/o worker threads

    var worker_threads = try std.ArrayListUnmanaged(std.Thread).initCapacity(allocator, worker_count - 1);
    defer {
        // TODO: signal to worker thread to shutdown
        for (worker_threads.items) |*worker_thread| worker_thread.join();
        worker_threads.deinit(allocator);
    }
    for (workers.items[1..]) |*worker| {
        worker_threads.addOneAssumeCapacity().* = try std.Thread.spawn(.{}, Worker.run, .{worker});
    }

    // tcp listener

    var listener = try tcp.Listener.init(.ip, .{ .close_on_exec = true });
    defer listener.deinit();

    try listener.bind(ip.Address.initIPv4(IPv4.localhost, 0));
    try listener.listen(128);

    log.info("tcp: listening for peers on {}", .{try listener.getLocalAddress()});

    var listener_frame = async runListener(allocator, workers, listener);
    defer nosuspend await listener_frame catch |err| log.emerg("{}", .{err});

    try workers.items[0].run();
}

pub fn runListener(
    gpa: *mem.Allocator,
    workers: std.ArrayListUnmanaged(Worker),
    listener: tcp.Listener,
) !void {
    var next_worker_index: usize = 0;

    while (true) {
        const conn = workers.items[0].loop.accept(listener.socket.fd, .{ .close_on_exec = true }) catch |err| return err;
        errdefer conn.socket.deinit();

        const frame = try gpa.create(@Frame(runConnection));
        errdefer gpa.destroy(frame);

        const next_worker = &workers.items[next_worker_index];
        defer next_worker_index = (next_worker_index + 1) % workers.items.len;

        frame.* = async runConnection(gpa, next_worker, tcp.Connection.from(conn));
        next_worker.loop.notify();
    }
}

pub fn runConnection(gpa: *mem.Allocator, worker: *Worker, conn: tcp.Connection) !void {
    defer {
        conn.deinit();
        suspend gpa.destroy(@frame());
    }

    log.debug("new peer connected: {}", .{conn.address});

    var buffer: [256]u8 = undefined;

    while (true) {
        const num_bytes_read = worker.loop.recv(conn.client.socket.fd, &buffer, 0) catch |err| return err;
        if (num_bytes_read == 0) return;

        log.debug("{}: got message: '{s}'", .{ conn.address, mem.trim(u8, buffer[0..num_bytes_read], " \t\r\n") });
    }
}
