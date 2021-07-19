const std = @import("std");

const os = std.os;
const mem = std.mem;
const math = std.math;
const time = std.time;
const log = std.log.scoped(.client);

const ip = std.x.net.ip;
const tcp = std.x.net.tcp;
const testing = std.testing;

const assert = std.debug.assert;

const binary = @import("binary.zig");

const RPC = @import("RPC.zig");
const Loop = @import("Loop.zig");
const Packet = @import("Packet.zig");
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
    writer: std.TailQueue(Worker.Task).Node,
};

address: ip.Address,

timer: Loop.Timer,
closed: bool = false,

capacity: usize,

queue: std.SinglyLinkedList([]const u8) = .{},
queue_len: usize = 0,

rpc: RPC,
pool: []*Client.Connection,
next_worker_index: usize = 0,

pending: struct {
    connection_available: std.SinglyLinkedList(Client.Connection.Waiter) = .{},
    connecting: std.SinglyLinkedList(anyframe) = .{},
    writes: std.SinglyLinkedList(Worker.Task) = .{},
    writers: std.TailQueue(Worker.Task) = .{},
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

    fn unparkAttemptToConnect(self: *@This(), waiter: *std.SinglyLinkedList(anyframe).Node) void {
        assert(self.connecting.popFirst() == waiter);
        const next_waiter = waiter.removeNext() orelse return;
        resume next_waiter.data;
    }

    fn parkUntilWriterNeeded(self: *@This(), conn: *Client.Connection) void {
        conn.writer = .{ .data = .{ .value = @frame() } };
        suspend self.writers.append(&conn.writer);
    }

    fn parkUntilMayWrite(self: *@This()) void {
        var waiter: std.SinglyLinkedList(Worker.Task).Node = .{ .data = .{ .value = @frame() } };
        suspend self.writes.prepend(&waiter);
    }

    fn unparkWriteRequests(self: *@This(), runtime: *Runtime) void {
        while (self.writes.popFirst()) |waiter| {
            runtime.schedule(0, &waiter.data);
        }
    }

    fn removeWriter(self: *@This(), runtime: *Runtime, conn: *Client.Connection) void {
        if (self.writers.len == 0) return;
        if (self.writers.first != &conn.writer and conn.writer.prev == null and conn.writer.next == null) return;

        self.writers.remove(&conn.writer);
        conn.writer.next = null;
        conn.writer.prev = null;

        runtime.schedule(conn.worker_index, &conn.writer.data);
    }

    fn wakeUpWriter(self: *@This(), runtime: *Runtime) void {
        const writer = self.writers.popFirst() orelse return;
        writer.next = null;
        writer.prev = null;

        const conn = @fieldParentPtr(Client.Connection, "writer", writer);
        runtime.schedule(conn.worker_index, &writer.data);
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
        self.last_time_attempt_failed = time.milliTimestamp();
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
        if (time.milliTimestamp() - self.last_time_attempt_failed > 30_000) return .half_open;
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

    const rpc = try RPC.init(gpa, 65536);
    errdefer rpc.deinit(gpa);

    var timer = Loop.Timer.init(&runtime.workers.items[0].loop);

    var client = Client{
        .address = address,

        .timer = timer,

        .rpc = rpc,
        .pool = pool,
        .capacity = capacity,
    };

    client.pool.len = 0;

    return client;
}

pub fn deinit(self: *Client, gpa: *mem.Allocator) void {
    self.rpc.deinit(gpa);

    while (self.queue.popFirst()) |node| {
        gpa.destroy(node);
    }
    self.queue_len = 0;

    self.pool.len = self.capacity;
    for (self.pool) |conn| {
        gpa.destroy(conn);
    }
    gpa.free(self.pool);
}

pub fn shutdown(self: *Client, runtime: *Runtime) void {
    self.closed = true;

    for (self.pool) |conn| {
        const client = conn.client orelse continue;
        client.shutdown(.recv) catch {};
    }

    self.rpc.shutdown(runtime);
    self.timer.cancel();
}

pub fn waitForShutdown(self: *Client) void {
    if (self.pool.len > 0) {
        self.pending.parkUntilShutdownCompleted();
    }
}

pub fn ensureConnectionAvailable(self: *Client, runtime: *Runtime) !void {
    if (self.closed) return error.Closed;

    if (self.pool.len == 0 or (self.queue_len > 0 and self.pool.len < self.capacity)) {
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

pub fn write(self: *Client, runtime: *Runtime, node: *std.SinglyLinkedList([]const u8).Node) !void {
    try self.ensureConnectionAvailable(runtime);

    while (node.data.len + self.queue_len > 4 * 1024 * 1024) {
        if (self.closed) return error.Closed;
        self.pending.parkUntilMayWrite();
    }
    self.queue.prepend(node);
    self.queue_len += node.data.len;

    self.pending.wakeUpWriter(runtime);
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
    var writer_done = false;
    var writer_frame = async self.runWriteLoop(runtime, conn, &writer_done);
    var reader_frame = async self.runReadLoop(runtime, conn);

    await reader_frame catch {};
    runtime.yield(0);

    {
        writer_done = true;
        self.pending.removeWriter(runtime, conn);
    }

    await writer_frame catch {};
    runtime.yield(0);
}

fn runReadLoop(self: *Client, runtime: *Runtime, conn: *Client.Connection) !void {
    runtime.yield(conn.worker_index);

    const loop = &runtime.workers.items[conn.worker_index].loop;
    const client = conn.client orelse unreachable;

    var buffer = std.fifo.LinearFifo(u8, .Dynamic).init(runtime.gpa);
    defer buffer.deinit();

    while (true) {
        while (buffer.count < @sizeOf(u32)) {
            const num_bytes_read = try loop.recv(client.socket.fd, try buffer.writableWithSize(65536), 0);
            if (num_bytes_read == 0) return error.EndOfFile;
            buffer.update(num_bytes_read);
        }

        var size: u32 = undefined;

        var size_pos: usize = 0;
        while (size_pos < @sizeOf(u32)) {
            size_pos += buffer.read(mem.asBytes(&size)[size_pos..]);
        }

        size = try binary.decode(u32, mem.asBytes(&size));
        if (size < @sizeOf(u32)) return error.MessageSizeTooSmall;
        if (size > 65536) return error.MessageSizeTooLarge;

        size -= @sizeOf(u32);

        while (buffer.count < size) {
            const num_bytes_read = try loop.recv(client.socket.fd, try buffer.writableWithSize(65536), 0);
            if (num_bytes_read == 0) return error.EndOfFile;
            buffer.update(num_bytes_read);
        }

        const message = try runtime.gpa.alloc(u8, size);
        defer runtime.gpa.free(message); // make it errdefer after implementing message handling

        var message_pos: usize = 0;
        while (message_pos < size) {
            message_pos += buffer.read(message[message_pos..]);
        }

        const packet = try Packet.unmarshal(message);

        switch (packet.get(.type)) {
            .response => {
                if (self.rpc.unpark(runtime, packet, message[packet.buffer.len..])) {
                    continue;
                }
            },
            else => {},
        }
    }
}

fn runWriteLoop(self: *Client, runtime: *Runtime, conn: *Client.Connection, writer_done: *const bool) !void {
    runtime.yield(conn.worker_index);

    const loop = &runtime.workers.items[conn.worker_index].loop;
    const client = conn.client orelse unreachable;

    var buffer: [65536]u8 = undefined;
    var pos: usize = 0;

    var pending: std.SinglyLinkedList([]const u8) = .{};
    defer if (pending.first != null) {
        runtime.yield(0);
        defer runtime.yield(conn.worker_index);

        while (pending.popFirst()) |node| : (self.queue_len += node.data.len) {
            self.queue.prepend(node);
        }
    };

    while (true) {
        await async runtime.yield(0);

        if (self.queue.first) |first| {
            pending.first = first;
            self.queue.first = null;
            self.queue_len = 0;
            self.pending.unparkWriteRequests(runtime);
        } else {
            if (self.closed or writer_done.*) {
                return error.Closed;
            }
            self.pending.parkUntilWriterNeeded(conn);
            continue;
        }

        await async runtime.yield(conn.worker_index);

        var count: usize = 0;

        while (pending.popFirst()) |node| : (count += 1) {
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
    defer self.pending.unparkAttemptToConnect(&waiter);

    if (self.circuit_breaker.tripped()) return error.CircuitBreakerTripped;

    if (self.circuit_breaker.num_failed_attempts > 0 and self.circuit_breaker.last_time_attempt_failed > 0) {
        const delay_max: i64 = 3000 * time.ns_per_ms;
        const delay_step: i64 = 10 * time.ns_per_ms;
        const delay = math.min(delay_max, delay_step * math.shl(i64, 1, self.circuit_breaker.num_failed_attempts - 1));

        log.debug("{} [{}] reconnection attempt #{}: will retry in {} milliseconds", .{
            self.address,
            conn.worker_index,
            self.circuit_breaker.num_failed_attempts,
            @divTrunc(delay, time.ns_per_ms),
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
