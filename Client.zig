const std = @import("std");

const os = std.os;
const mem = std.mem;
const math = std.math;
const log = std.log.scoped(.client);

const ip = std.x.net.ip;
const tcp = std.x.net.tcp;
const testing = std.testing;

const assert = std.debug.assert;

const Loop = @import("Loop.zig");
const Worker = @import("Worker.zig");
const Runtime = @import("Runtime.zig");

const Client = @This();

pub const Connection = struct {
    pub const Waiter = struct {
        frame: anyframe,
        result: ?anyerror = null,
    };

    worker_index: usize,
    client: ?tcp.Client = null,
    frame: @Frame(Client.serve),
    writer: Worker.Task,
};

address: ip.Address,

timer: Loop.Timer,
queue: std.SinglyLinkedList([]const u8) = .{},
next_worker_index: usize = 0,
closed: bool = false,

pool: []*Client.Connection,
capacity: usize,

pending: struct {
    connection_available: std.SinglyLinkedList(Client.Connection.Waiter) = .{},
    connecting: std.SinglyLinkedList(anyframe) = .{},
    writers: std.TailQueue(*Worker.Task) = .{},
    shutdown: std.SinglyLinkedList(anyframe) = .{},

    fn parkUntilConnectionAvailable(self: *@This()) !void {
        var waiter: std.SinglyLinkedList(Client.Connection.Waiter).Node = .{ .data = .{ .frame = @frame() } };
        suspend self.connection_available.prepend(&waiter);
        if (waiter.data.result) |result| return result;
    }

    fn reportConnectionResult(self: *@This(), result: ?anyerror) void {
        while (self.connection_available.popFirst()) |node| {
            node.data.result = result;
            resume node.data.frame;
        }
    }

    fn parkUntilMayAttemptToConnect(self: *@This(), waiter: *std.SinglyLinkedList(anyframe).Node) void {
        const first = self.connecting.first orelse return self.connecting.prepend(waiter);
        waiter.data = @frame();
        suspend first.insertAfter(waiter);
    }

    fn unparkConnectAttempt(self: *@This(), waiter: *std.SinglyLinkedList(anyframe).Node) void {
        assert(self.connecting.popFirst() == waiter);
        const next_waiter = waiter.removeNext() orelse return;
        resume next_waiter.data;
    }

    fn parkUntilWriterNeeded(self: *@This(), conn: *Client.Connection) void {
        conn.writer = .{ .value = @frame() };
        var node: std.TailQueue(*Worker.Task).Node = .{ .data = &conn.writer };
        suspend self.writers.append(&node);
    }

    fn wakeUpWriter(self: *@This(), runtime: *Runtime) void {
        const node = self.writers.popFirst() orelse return;
        const conn = @fieldParentPtr(Client.Connection, "writer", node.data);
        runtime.schedule(0, conn.worker_index, &conn.writer);
    }

    fn wakeUpWriters(self: *@This(), runtime: *Runtime) void {
        while (self.writers.popFirst()) |node| {
            const conn = @fieldParentPtr(Client.Connection, "writer", node.data);
            runtime.schedule(0, conn.worker_index, &conn.writer);
        }
    }

    fn parkUntilShutdownCompleted(self: *@This()) void {
        var waiter: std.SinglyLinkedList(anyframe).Node = .{ .data = @frame() };
        suspend self.shutdown.prepend(&waiter);
    }

    fn reportShutdownCompleted(self: *@This()) void {
        while (self.shutdown.popFirst()) |node| resume node.data;
    }
} = .{},

circuit_breaker: struct {
    num_failed_attempts: u64 = math.maxInt(u64),
    last_time_attempt_failed: i64 = 0,

    pub fn reportSuccess(self: *@This()) void {
        self.num_failed_attempts = 0;
        self.last_time_attempt_failed = 0;
    }

    pub fn reportFailure(self: *@This()) void {
        self.num_failed_attempts = math.add(u64, self.num_failed_attempts, 1) catch self.num_failed_attempts;
        self.last_time_attempt_failed = std.time.milliTimestamp();
    }

    pub fn tripped(self: @This()) bool {
        return self.state() == .open;
    }

    pub fn state(self: @This()) enum {
        open,
        half_open,
        closed,
    } {
        if (self.num_failed_attempts <= 10) return .closed;
        if (std.time.milliTimestamp() - self.last_time_attempt_failed > 30_000) return .half_open;
        return .open;
    }
} = .{},

pub fn init(gpa: *mem.Allocator, runtime: *Runtime, address: ip.Address) !Client {
    const capacity = 4;

    const pool = try gpa.alloc(*Client.Connection, capacity);
    errdefer gpa.free(pool);

    var pool_index: usize = 0;
    errdefer for (pool[0..pool_index]) |conn| gpa.destroy(conn);

    while (pool_index < capacity) : (pool_index += 1) {
        pool[pool_index] = try gpa.create(Client.Connection);
    }

    var timer = Loop.Timer.init(&runtime.workers.items[0].loop);

    var client = Client{
        .address = address,
        .timer = timer,
        .pool = pool,
        .capacity = capacity,
    };

    client.pool.len = 0;

    return client;
}

pub fn deinit(self: *Client, gpa: *mem.Allocator) void {
    while (self.queue.popFirst()) |node| {
        gpa.destroy(node);
    }
    self.pool.len = self.capacity;
    for (self.pool) |conn| {
        gpa.destroy(conn);
    }
    gpa.free(self.pool);
}

pub fn shutdown(self: *Client, runtime: *Runtime) void {
    self.closed = true;
    self.timer.cancel();

    for (self.pool) |conn| {
        if (conn.client) |*client| {
            client.shutdown(.recv) catch {};
        }
    }

    self.pending.wakeUpWriters(runtime);
}

pub fn waitForShutdown(self: *Client) void {
    if (self.pool.len > 0) {
        self.pending.parkUntilShutdownCompleted();
    }
}

pub fn write(self: *Client, runtime: *Runtime, message: []const u8) !void {
    try self.ensureConnectionAvailable(runtime);

    const buf = try runtime.gpa.create(std.SinglyLinkedList([]const u8).Node);
    buf.* = .{ .data = message };
    self.queue.prepend(buf);

    self.pending.wakeUpWriter(runtime);
}

pub fn ensureConnectionAvailable(self: *Client, runtime: *Runtime) !void {
    if (self.closed) return error.Closed;

    if (self.pool.len == 0 or (self.queue.first != null and self.pool.len < self.capacity)) {
        self.pool.len += 1;

        self.pool[self.pool.len - 1].worker_index = self.next_worker_index;
        self.next_worker_index = (self.next_worker_index + 1) % runtime.worker_count;

        log.info("{} [{}] is being spawned", .{ self.address, self.pool[self.pool.len - 1].worker_index });

        self.pool[self.pool.len - 1].client = null;
        self.pool[self.pool.len - 1].frame = async self.serve(runtime, self.pool[self.pool.len - 1]);
    }

    const connection_available = for (self.pool) |conn| {
        if (conn.client != null) break true;
    } else false;

    if (connection_available) return;

    try self.pending.parkUntilConnectionAvailable();
}

fn serve(self: *Client, runtime: *Runtime, conn: *Client.Connection) void {
    defer {
        suspend self.markClosed(conn);
    }

    while (true) {
        const client = self.connect(runtime, conn) catch |err| {
            if (self.markError(conn, err)) {
                return;
            }
            continue;
        };
        defer client.deinit();

        if (!self.markReady(conn, client)) {
            return;
        }

        self.runIoLoops(runtime, conn);

        if (self.markDisconnected(conn)) {
            return;
        }
    }
}

fn runIoLoops(self: *Client, runtime: *Runtime, conn: *Client.Connection) void {
    runtime.yield(0, conn.worker_index);
    defer runtime.yield(conn.worker_index, 0);

    var read_frame = async self.runReadLoop(runtime, conn);
    var write_frame = async self.runWriteLoop(runtime, conn);

    _ = await read_frame;
    conn.client.?.shutdown(.send) catch {};
    _ = await write_frame;
}

fn runReadLoop(_: *Client, runtime: *Runtime, conn: *Client.Connection) !void {
    const loop = &runtime.workers.items[conn.worker_index].loop;

    var buffer: [65536]u8 = undefined;

    while (conn.client) |client| {
        const num_bytes_read = try loop.recv(client.socket.fd, &buffer, 0);
        if (num_bytes_read == 0) break;
    }
}

fn runWriteLoop(self: *Client, runtime: *Runtime, conn: *Client.Connection) !void {
    const loop = &runtime.workers.items[conn.worker_index].loop;

    var buffer: [65536]u8 = undefined;
    var pos: usize = 0;

    var pending: std.SinglyLinkedList([]const u8) = .{};
    defer if (pending.first != null) {
        runtime.yield(conn.worker_index, 0);
        defer runtime.yield(0, conn.worker_index);

        while (pending.popFirst()) |node| {
            self.queue.prepend(node);
        }
    };

    while (conn.client) |client| {
        runtime.yield(conn.worker_index, 0);

        if (self.queue.first) |first| {
            pending.first = first;
            self.queue.first = null;
        } else {
            if (self.closed) return error.Closed;
            self.pending.parkUntilWriterNeeded(conn);
            continue;
        }

        runtime.yield(0, conn.worker_index);

        while (pending.popFirst()) |node| {
            defer runtime.gpa.destroy(node);

            if (node.data.len >= buffer[pos..].len) {
                // If a queued message cannot fit into the buffer, do a dedicated send() on
                // the message rather than attempt to have it fit inside the buffer.

                if (node.data.len > buffer.len) {
                    @setCold(true);
                    try writeAll(loop, client, node.data);
                    continue;
                }

                try writeAll(loop, client, buffer[0..pos]);
                pos = 0;
            }

            mem.copy(u8, buffer[pos..], node.data);
            pos += node.data.len;
        }

        try writeAll(loop, client, buffer[0..pos]);
        pos = 0;
    }
}

fn connect(self: *Client, runtime: *Runtime, conn: *Client.Connection) !tcp.Client {
    var waiter: std.SinglyLinkedList(anyframe).Node = undefined;
    self.pending.parkUntilMayAttemptToConnect(&waiter);
    defer self.pending.unparkConnectAttempt(&waiter);

    if (self.circuit_breaker.tripped()) return error.CircuitBreakerTripped;

    if (self.circuit_breaker.num_failed_attempts > 0 and self.circuit_breaker.last_time_attempt_failed > 0) {
        const delay_max: i64 = 3000 * std.time.ns_per_ms;
        const delay_step: i64 = 10 * std.time.ns_per_ms;
        const delay = math.min(delay_max, delay_step * math.shl(i64, 1, self.circuit_breaker.num_failed_attempts - 1));

        log.debug("{} [{}] reconnection attempt #{}: will retry in {} milliseconds", .{
            self.address,
            conn.worker_index,
            self.circuit_breaker.num_failed_attempts,
            @divTrunc(delay, std.time.ns_per_ms),
        });

        try self.timer.waitFor(.{ .nanoseconds = delay });
    }

    const client = try tcp.Client.init(.ip, .{ .close_on_exec = true });
    errdefer client.deinit();

    try client.setNoDelay(true);
    try runtime.workers.items[0].loop.connect(client.socket.fd, self.address.into());

    return client;
}

fn writeAll(loop: *Loop, client: tcp.Client, buffer: []const u8) !void {
    var index: usize = 0;
    while (index < buffer.len) {
        index += try loop.send(client.socket.fd, buffer[index..], os.MSG_NOSIGNAL);
    }
}

fn markReady(self: *Client, conn: *Client.Connection, client: tcp.Client) bool {
    if (self.closed) return false;

    log.debug("{} [{}] is connected and ready", .{ self.address, conn.worker_index });

    assert(conn.client == null);
    conn.client = client;

    self.circuit_breaker.reportSuccess();
    self.pending.reportConnectionResult(null);

    return true;
}

fn markError(self: *Client, conn: *Client.Connection, err: anyerror) bool {
    log.debug("{} [{}] tried to connect and failed: {}", .{ self.address, conn.worker_index, err });

    self.circuit_breaker.reportFailure();
    if (self.pool.len > 1) return true;
    if (!self.closed and err != error.CircuitBreakerTripped) return false;

    log.debug("{} [{}] additionally reported a connect error: {}", .{ self.address, conn.worker_index, err });
    self.pending.reportConnectionResult(err);

    return true;
}

fn markDisconnected(self: *Client, conn: *Client.Connection) bool {
    assert(conn.client != null);
    conn.client = null;

    return self.closed or self.pool.len > 1;
}

fn markClosed(self: *Client, conn: *Client.Connection) void {
    log.debug("{} [{}] was closed", .{ self.address, conn.worker_index });

    const i = mem.indexOfScalar(*Client.Connection, self.pool, conn).?;
    mem.swap(*Client.Connection, &self.pool[i], &self.pool[self.pool.len - 1]);

    self.pool.len -= 1;
    if (self.pool.len == 0) {
        self.pending.reportShutdownCompleted();
    }
}

test {
    testing.refAllDecls(@This());
}
