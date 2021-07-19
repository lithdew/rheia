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
const Lock = @import("Lock.zig");
const Loop = @import("Loop.zig");
const Packet = @import("Packet.zig");
const Worker = @import("Worker.zig");
const Runtime = @import("Runtime.zig");

const SinglyLinkedList = @import("intrusive.zig").SinglyLinkedList;
const DoublyLinkedDeque = @import("intrusive.zig").DoublyLinkedDeque;

const Client = @This();

pub const Connection = struct {
    pub const Result = struct {
        next: ?*Client.Connection.Result = null,
        worker_id: usize,
        task: Worker.Task,
        result: ?anyerror = null,
    };

    pub const Waiter = struct {
        next: ?*Waiter = null,
        worker_id: usize,
        task: Worker.Task,
    };

    pub const Writer = struct {
        next: ?*Writer = null,
        prev: ?*Writer = null,
        task: Worker.Task,
    };

    worker_id: usize,
    client: ?tcp.Client = null,
    frame: @Frame(Client.serve),
    writer: Client.Connection.Writer,
};

address: ip.Address,

timers: std.ArrayListUnmanaged(Loop.Timer) = .{},
closed: bool = false,

capacity: usize,

queue: std.SinglyLinkedList([]const u8) = .{},
num_bytes_queued: usize = 0,

rpc: RPC,
pool: []*Client.Connection,
next_worker_id: usize = 0,

lock: Lock = .{},
connect_attempt: Lock = .{},

pending: struct {
    writes: SinglyLinkedList(Client.Connection.Waiter, .next) = .{},
    shutdown: SinglyLinkedList(Client.Connection.Waiter, .next) = .{},
    writers: DoublyLinkedDeque(Client.Connection.Writer, .next, .prev) = .{},
    connection_available: SinglyLinkedList(Client.Connection.Result, .next) = .{},

    fn reportConnectionResult(self: *@This(), runtime: *Runtime, result: ?anyerror) void {
        while (self.connection_available.popFirst()) |waiter| {
            waiter.result = result;
            runtime.scheduleTo(waiter.worker_id, &waiter.task);
        }
    }

    fn unparkWriteRequests(self: *@This(), runtime: *Runtime) void {
        while (self.writes.popFirst()) |waiter| {
            runtime.scheduleTo(waiter.worker_id, &waiter.task);
        }
    }

    fn wakeUpWriter(self: *@This(), runtime: *Runtime) void {
        const writer = self.writers.popFirst() orelse return;
        const conn = @fieldParentPtr(Client.Connection, "writer", writer);
        runtime.scheduleTo(conn.worker_id, &writer.task);
    }

    fn reportShutdownCompleted(self: *@This(), runtime: *Runtime) void {
        while (self.shutdown.popFirst()) |waiter| {
            runtime.scheduleTo(waiter.worker_id, &waiter.task);
        }
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

    var rpc = try RPC.init(gpa, 65536);
    errdefer rpc.deinit(gpa);

    var timers = try std.ArrayListUnmanaged(Loop.Timer).initCapacity(gpa, runtime.worker_count);
    errdefer timers.deinit(gpa);

    for (timers.items.ptr[0..runtime.worker_count]) |*timer, i| {
        timer.* = Loop.Timer.init(&runtime.workers.items[i].loop);
    }
    timers.items.len = runtime.worker_count;

    var client = Client{
        .address = address,

        .timers = timers,

        .rpc = rpc,
        .pool = pool,
        .capacity = capacity,
    };

    client.pool.len = 0;

    return client;
}

pub fn deinit(self: *Client, gpa: *mem.Allocator) void {
    self.timers.deinit(gpa);
    self.rpc.deinit(gpa);

    while (self.queue.popFirst()) |node| {
        gpa.destroy(node);
    }
    self.num_bytes_queued = 0;

    self.pool.len = self.capacity;
    for (self.pool) |conn| {
        gpa.destroy(conn);
    }
    gpa.free(self.pool);
}

pub fn shutdown(self: *Client, runtime: *Runtime) void {
    self.lock.acquire();
    self.closed = true;

    for (self.pool) |conn| {
        const client = conn.client orelse continue;
        client.shutdown(.recv) catch {};
    }
    self.lock.release(runtime);

    self.rpc.shutdown(runtime);

    // TODO: cancel timers
}

pub fn waitForShutdown(self: *Client, runtime: *Runtime) void {
    self.lock.acquire();
    if (self.pool.len > 0) {
        var waiter: Client.Connection.Waiter = .{
            .worker_id = Worker.getCurrent().id,
            .task = .{ .value = @frame() },
        };
        suspend {
            self.pending.shutdown.prepend(&waiter);
            self.lock.release(runtime);
        }
    } else {
        self.lock.release(runtime);
    }
}

pub fn ensureConnectionAvailable(self: *Client, runtime: *Runtime) !void {
    self.lock.acquire();

    if (self.closed) {
        self.lock.release(runtime);
        return error.Closed;
    }

    if (self.pool.len == 0 or (self.num_bytes_queued > 0 and self.pool.len < self.capacity)) {
        self.pool.len += 1;

        self.pool[self.pool.len - 1].worker_id = self.next_worker_id;
        self.next_worker_id = (self.next_worker_id + 1) % runtime.worker_count;

        log.info("{} [{}] is being spawned", .{ self.address, self.pool[self.pool.len - 1].worker_id });

        self.pool[self.pool.len - 1].client = null;
        self.pool[self.pool.len - 1].frame = async self.serve(runtime, self.pool[self.pool.len - 1]);
    }

    const connection_available = for (self.pool) |conn| {
        if (conn.client != null) break true;
    } else false;

    if (connection_available) {
        self.lock.release(runtime);
        return;
    }

    var waiter: Client.Connection.Result = .{
        .worker_id = Worker.getCurrent().id,
        .task = .{ .value = @frame() },
    };
    suspend {
        self.pending.connection_available.prepend(&waiter);
        self.lock.release(runtime);
    }
    if (waiter.result) |result| return result;
}

pub fn write(self: *Client, runtime: *Runtime, node: *std.SinglyLinkedList([]const u8).Node) !void {
    try self.ensureConnectionAvailable(runtime);

    self.lock.acquire();
    while (node.data.len + self.num_bytes_queued > 4 * 1024 * 1024) {
        if (self.closed) {
            self.lock.release(runtime);
            return error.Closed;
        }

        var waiter: Client.Connection.Waiter = .{
            .worker_id = Worker.getCurrent().id,
            .task = .{ .value = @frame() },
        };
        suspend {
            self.pending.writes.prepend(&waiter);
            self.lock.release(runtime);
        }
        self.lock.acquire();
    }

    self.queue.prepend(node);
    self.num_bytes_queued += node.data.len;

    self.pending.wakeUpWriter(runtime);
    self.lock.release(runtime);
}

fn serve(self: *Client, runtime: *Runtime, conn: *Client.Connection) void {
    runtime.yield(conn.worker_id);

    defer {
        suspend self.markClosed(runtime, conn);
    }

    while (true) {
        const client = self.connect(runtime, conn) catch |err| {
            if (self.markError(runtime, conn, err)) {
                return;
            }
            continue;
        };
        defer client.deinit();

        if (!self.markReady(runtime, conn, client)) {
            return;
        }

        self.runIoLoops(runtime, conn);

        if (self.markDisconnected(runtime, conn)) {
            return;
        }
    }
}

fn runIoLoops(self: *Client, runtime: *Runtime, conn: *Client.Connection) void {
    var writer_done = false;
    var writer_frame = async self.runWriteLoop(runtime, conn, &writer_done);
    var reader_frame = async self.runReadLoop(runtime, conn);

    await reader_frame catch {};

    {
        self.lock.acquire();
        defer self.lock.release(runtime);

        writer_done = true;
        if (self.pending.writers.remove(&conn.writer)) {
            runtime.schedule(&conn.writer.task);
        }
    }

    await writer_frame catch {};
}

fn runReadLoop(self: *Client, runtime: *Runtime, conn: *Client.Connection) !void {
    const loop = &Worker.getCurrent().loop;
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
    const loop = &Worker.getCurrent().loop;
    const client = conn.client orelse unreachable;

    var buffer: [65536]u8 = undefined;
    var pos: usize = 0;

    var pending: std.SinglyLinkedList([]const u8) = .{};
    defer if (pending.first != null) {
        self.lock.acquire();
        defer self.lock.release(runtime);

        while (pending.popFirst()) |node| : (self.num_bytes_queued += node.data.len) {
            self.queue.prepend(node);
        }
    };

    while (true) {
        self.lock.acquire();
        if (self.queue.first) |first| {
            self.queue.first = null;
            pending.first = first;

            self.num_bytes_queued = 0;
            self.pending.unparkWriteRequests(runtime);
        } else {
            if (self.closed or writer_done.*) {
                self.lock.release(runtime);
                return error.Closed;
            }
            conn.writer = .{ .task = .{ .value = @frame() } };
            suspend {
                self.pending.writers.append(&conn.writer);
                self.lock.release(runtime);
            }
            continue;
        }
        self.lock.release(runtime);

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
    self.connect_attempt.acquire();
    defer self.connect_attempt.release(runtime);

    const backoff_delay: ?i64 = backoff_delay: {
        self.lock.acquire();
        defer self.lock.release(runtime);

        if (self.circuit_breaker.tripped()) return error.CircuitBreakerTripped;

        if (self.circuit_breaker.num_failed_attempts > 0 and self.circuit_breaker.last_time_attempt_failed > 0) {
            const delay_max: i64 = 3000 * time.ns_per_ms;
            const delay_step: i64 = 10 * time.ns_per_ms;
            const delay = math.min(delay_max, delay_step * math.shl(i64, 1, self.circuit_breaker.num_failed_attempts - 1));

            log.debug("{} [{}] reconnection attempt #{}: will retry in {} milliseconds", .{
                self.address,
                conn.worker_id,
                self.circuit_breaker.num_failed_attempts,
                @divTrunc(delay, time.ns_per_ms),
            });

            break :backoff_delay delay;
        }
        break :backoff_delay null;
    };

    if (backoff_delay) |duration| {
        try self.timers.items[conn.worker_id].waitFor(.{ .nanoseconds = duration });
    }

    const client = try tcp.Client.init(.ip, .{ .close_on_exec = true });
    errdefer client.deinit();

    try client.setNoDelay(true);
    try runtime.workers.items[conn.worker_id].loop.connect(client.socket.fd, self.address.into());

    return client;
}

fn writeAll(loop: *Loop, client: tcp.Client, buffer: []const u8) !void {
    var index: usize = 0;
    while (index < buffer.len) {
        index += try loop.send(client.socket.fd, buffer[index..], os.MSG_NOSIGNAL);
    }
}

fn markReady(self: *Client, runtime: *Runtime, conn: *Client.Connection, client: tcp.Client) bool {
    self.lock.acquire();
    defer self.lock.release(runtime);

    if (self.closed) return false;

    log.debug("{} [{}] is connected and ready", .{ self.address, conn.worker_id });

    assert(conn.client == null);
    conn.client = client;

    self.circuit_breaker.reportSuccess();
    self.pending.reportConnectionResult(runtime, null);

    return true;
}

fn markError(self: *Client, runtime: *Runtime, conn: *Client.Connection, err: anyerror) bool {
    self.lock.acquire();
    defer self.lock.release(runtime);

    log.debug("{} [{}] tried to connect and failed: {}", .{ self.address, conn.worker_id, err });

    self.circuit_breaker.reportFailure();
    if (self.pool.len > 1) return true;
    if (!self.closed and err != error.CircuitBreakerTripped) return false;

    log.debug("{} [{}] additionally reported a connect error: {}", .{ self.address, conn.worker_id, err });
    self.pending.reportConnectionResult(runtime, err);

    return true;
}

fn markDisconnected(self: *Client, runtime: *Runtime, conn: *Client.Connection) bool {
    self.lock.acquire();
    defer self.lock.release(runtime);

    assert(conn.client != null);
    conn.client = null;

    return self.closed or self.pool.len > 1;
}

fn markClosed(self: *Client, runtime: *Runtime, conn: *Client.Connection) void {
    self.lock.acquire();
    defer self.lock.release(runtime);

    log.debug("{} [{}] was closed", .{ self.address, conn.worker_id });

    const i = mem.indexOfScalar(*Client.Connection, self.pool, conn).?;
    mem.swap(*Client.Connection, &self.pool[i], &self.pool[self.pool.len - 1]);

    self.pool.len -= 1;
    if (self.pool.len == 0) {
        self.pending.reportShutdownCompleted(runtime);
    }
}

test {
    testing.refAllDecls(@This());
}
