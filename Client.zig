const std = @import("std");

const os = std.os;
const ip = std.x.net.ip;
const mem = std.mem;
const tcp = std.x.net.tcp;
const log = std.log.scoped(.client);
const math = std.math;
const time = std.time;
const sync = @import("sync.zig");
const binary = @import("binary.zig");
const testing = std.testing;

const assert = std.debug.assert;

const Packet = @import("Packet.zig");
const runtime = @import("runtime.zig");

const SinglyLinkedList = @import("intrusive.zig").SinglyLinkedList;
const DoublyLinkedDeque = @import("intrusive.zig").DoublyLinkedDeque;

const Client = @This();

pub const Connection = struct {
    pub const Result = struct {
        next: ?*Client.Connection.Result = null,
        prev: ?*Client.Connection.Result = null,
        worker_id: usize,
        task: runtime.Task,
        result: ?anyerror = null,
    };

    pub const Waiter = struct {
        next: ?*Client.Connection.Waiter = null,
        prev: ?*Client.Connection.Waiter = null,
        worker_id: usize,
        task: runtime.Task,
    };

    client: ?tcp.Client = null,
    frame: @Frame(Client.serve),
    writer: Client.Connection.Waiter,
};

pub const CircuitBreaker = struct {
    pub const State = enum {
        open,
        half_open,
        closed,
    };

    lock: sync.Lock = .{},
    num_failed_attempts: u64 = math.maxInt(u64),
    last_time_attempt_failed: i64 = 0,

    pub fn reportSuccess(self: *CircuitBreaker) void {
        self.lock.acquire();
        defer self.lock.release();

        self.num_failed_attempts = 0;
        self.last_time_attempt_failed = 0;
    }

    pub fn reportFailure(self: *CircuitBreaker) void {
        self.lock.acquire();
        defer self.lock.release();

        self.num_failed_attempts = math.add(u64, self.num_failed_attempts, 1) catch self.num_failed_attempts;
        self.last_time_attempt_failed = time.milliTimestamp();
    }

    pub fn tripped(self: *CircuitBreaker) bool {
        return self.state() == .open;
    }

    pub fn state(self: *CircuitBreaker) CircuitBreaker.State {
        self.lock.acquire();
        defer self.lock.release();

        if (self.num_failed_attempts <= 10) return .closed;
        if (time.milliTimestamp() - self.last_time_attempt_failed > 30_000) return .half_open;
        return .open;
    }

    pub fn hasFailuresReported(self: *CircuitBreaker) bool {
        self.lock.acquire();
        defer self.lock.release();

        return self.num_failed_attempts > 0 and self.last_time_attempt_failed > 0;
    }

    pub fn getNumReportedFailures(self: *CircuitBreaker) u64 {
        self.lock.acquire();
        defer self.lock.release();

        return self.num_failed_attempts;
    }
};

pub const RPC = struct {
    pub const Response = struct {
        header: Packet,
        data: []const u8,

        pub fn deinit(self: RPC.Response, gpa: *mem.Allocator) void {
            gpa.free(self.header.buffer.ptr[0 .. self.header.buffer.len + self.data.len]);
        }
    };

    pub const Waiter = struct {
        worker_id: usize,
        task: runtime.Task,
        result: ?Response = null,
    };

    lock: sync.Lock = .{},
    head: u32 = 0,
    tail: u32 = 0,
    entries: []?*RPC.Waiter,

    pub fn init(gpa: *mem.Allocator, capacity: usize) !RPC {
        assert(math.isPowerOfTwo(capacity));

        const entries = try gpa.alloc(?*RPC.Waiter, capacity);
        errdefer gpa.free(entries);

        mem.set(?*RPC.Waiter, entries, null);

        return RPC{ .entries = entries };
    }

    pub fn deinit(self: *RPC, gpa: *mem.Allocator) void {
        gpa.free(self.entries);
    }

    pub fn shutdown(self: *RPC) void {
        self.lock.acquire();
        defer self.lock.release();

        for (self.entries) |*maybe_waiter| {
            if (maybe_waiter.*) |waiter| {
                maybe_waiter.* = null;
                runtime.scheduleTo(waiter.worker_id, &waiter.task);
            }
        }
    }

    pub fn park(self: *RPC, waiter: *RPC.Waiter) !u32 {
        self.lock.acquire();
        defer self.lock.release();

        const nonce = self.head;
        if (nonce -% self.tail == self.entries.len) {
            return error.TooManyPendingRequests;
        }
        self.entries[nonce & (self.entries.len - 1)] = waiter;
        self.head +%= 1;
        return nonce;
    }

    pub fn cancel(self: *RPC, nonce: u32) ?*RPC.Waiter {
        self.lock.acquire();
        defer self.lock.release();

        const distance = nonce -% self.tail;
        if (distance >= self.entries.len) return null;

        const index = nonce & (self.entries.len - 1);
        const waiter = self.entries[index] orelse return null;
        self.entries[index] = null;

        return waiter;
    }

    pub fn unpark(self: *RPC, response: Response) bool {
        self.lock.acquire();
        defer self.lock.release();

        const nonce = response.header.get(.nonce);

        const distance = nonce -% self.tail;
        if (distance >= self.entries.len) return false;

        const index = nonce & (self.entries.len - 1);
        const waiter = self.entries[index] orelse return false;
        self.entries[index] = null;

        if (distance == 0) self.tail +%= 1;

        waiter.result = response;
        runtime.scheduleTo(waiter.worker_id, &waiter.task);

        return true;
    }
};

address: ip.Address,

closed: bool = false,

capacity: usize,

queue: std.SinglyLinkedList([]const u8) = .{},
num_bytes_queued: usize = 0,

rpc: RPC,
pool: []*Client.Connection,
next_worker_id: usize = 0,

lock: sync.Lock = .{},
connect_attempt: sync.Lock = .{},
connect_backoff: runtime.Request = .{},

pending: struct {
    writes: DoublyLinkedDeque(Client.Connection.Waiter, .next, .prev) = .{},
    shutdown: DoublyLinkedDeque(Client.Connection.Waiter, .next, .prev) = .{},
    writers: DoublyLinkedDeque(Client.Connection.Waiter, .next, .prev) = .{},
    connection_available: DoublyLinkedDeque(Client.Connection.Result, .next, .prev) = .{},

    fn reportConnectionResult(self: *@This(), result: ?anyerror) void {
        while (self.connection_available.popFirst()) |waiter| {
            waiter.result = result;
            runtime.scheduleTo(waiter.worker_id, &waiter.task);
        }
    }

    fn unparkWriteRequests(self: *@This()) void {
        while (self.writes.popFirst()) |waiter| {
            runtime.scheduleTo(waiter.worker_id, &waiter.task);
        }
    }

    fn wakeUpWriter(self: *@This()) void {
        const waiter = self.writers.popFirst() orelse return;
        runtime.scheduleTo(waiter.worker_id, &waiter.task);
    }

    fn reportShutdownCompleted(self: *@This()) void {
        while (self.shutdown.popFirst()) |waiter| {
            runtime.scheduleTo(waiter.worker_id, &waiter.task);
        }
    }
} = .{},

circuit_breaker: CircuitBreaker = .{},

pub fn init(gpa: *mem.Allocator, address: ip.Address) !Client {
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

    var client = Client{
        .address = address,
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
    self.num_bytes_queued = 0;

    self.pool.len = self.capacity;
    for (self.pool) |conn| {
        gpa.destroy(conn);
    }
    gpa.free(self.pool);
}

pub fn shutdown(self: *Client) void {
    self.lock.acquire();
    self.closed = true;

    for (self.pool) |conn| {
        const client = conn.client orelse continue;
        client.shutdown(.recv) catch {};
    }
    self.lock.release();

    self.rpc.shutdown();

    runtime.cancel(&self.connect_backoff);
}

pub fn join(self: *Client) void {
    self.lock.acquire();
    if (self.pool.len > 0) {
        var waiter: Client.Connection.Waiter = .{
            .worker_id = runtime.getCurrentWorkerId(),
            .task = .{ .frame = @frame() },
        };
        suspend {
            self.pending.shutdown.append(&waiter);
            self.lock.release();
        }
    } else {
        self.lock.release();
    }
}

pub fn ensureConnectionAvailable(self: *Client, gpa: *mem.Allocator) !void {
    self.lock.acquire();

    if (self.closed) {
        self.lock.release();
        return error.Closed;
    }

    if (self.pool.len == 0 or (self.num_bytes_queued > 0 and self.pool.len < self.capacity)) {
        self.pool.len += 1;

        const worker_id = self.next_worker_id;
        self.next_worker_id = (self.next_worker_id + 1) % runtime.getNumWorkers();

        log.info("{} [{}] is being spawned", .{ self.address, worker_id });

        self.pool[self.pool.len - 1].client = null;
        self.pool[self.pool.len - 1].frame = async self.serve(gpa, worker_id, self.pool[self.pool.len - 1]);
    }

    const connection_available = for (self.pool) |conn| {
        if (conn.client != null) break true;
    } else false;

    if (connection_available) {
        self.lock.release();
        return;
    }

    var waiter: Client.Connection.Result = .{
        .worker_id = runtime.getCurrentWorkerId(),
        .task = .{ .frame = @frame() },
    };

    suspend {
        self.pending.connection_available.append(&waiter);
        self.lock.release();
    }

    return waiter.result orelse {};
}

pub fn write(self: *Client, gpa: *mem.Allocator, node: *std.SinglyLinkedList([]const u8).Node) !void {
    try self.ensureConnectionAvailable(gpa);

    self.lock.acquire();
    defer self.lock.release();

    while (node.data.len + self.num_bytes_queued > 4 * 1024 * 1024) {
        if (self.closed) {
            return error.Closed;
        }

        var waiter: Client.Connection.Waiter = .{
            .worker_id = runtime.getCurrentWorkerId(),
            .task = .{ .frame = @frame() },
        };
        suspend {
            self.pending.writes.append(&waiter);
            self.lock.release();
        }
        self.lock.acquire();
    }

    self.queue.prepend(node);
    self.num_bytes_queued += node.data.len;

    self.pending.wakeUpWriter();
}

fn serve(self: *Client, gpa: *mem.Allocator, worker_id: usize, conn: *Client.Connection) void {
    runtime.yield(worker_id);

    defer {
        suspend self.markClosed(conn);
    }

    while (true) {
        const client = self.connect() catch |err| {
            if (self.markError(err)) {
                return;
            }
            continue;
        };
        defer client.deinit();

        if (!self.markReady(conn, client)) {
            return;
        }

        self.runIoLoops(gpa, conn);

        if (self.markDisconnected(conn)) {
            return;
        }
    }
}

fn runIoLoops(self: *Client, gpa: *mem.Allocator, conn: *Client.Connection) void {
    var writer_done = false;
    var writer_frame = async self.runWriteLoop(gpa, conn, &writer_done);
    var reader_frame = async self.runReadLoop(gpa, conn);

    await reader_frame catch {};

    {
        self.lock.acquire();
        defer self.lock.release();

        writer_done = true;
        if (self.pending.writers.remove(&conn.writer)) {
            runtime.schedule(&conn.writer.task);
        }
    }

    await writer_frame catch {};
}

fn runReadLoop(self: *Client, gpa: *mem.Allocator, conn: *Client.Connection) !void {
    const client = conn.client orelse unreachable;

    var buffer = std.fifo.LinearFifo(u8, .Dynamic).init(gpa);
    defer buffer.deinit();

    var request: runtime.Request = .{};

    while (true) {
        while (buffer.count < @sizeOf(u32)) {
            const num_bytes_read = try runtime.recv(&request, client.socket.fd, try buffer.writableWithSize(65536), 0);
            if (num_bytes_read == 0) return error.EndOfFile;
            buffer.update(num_bytes_read);
        }

        var size: u32 = undefined;
        try buffer.reader().readNoEof(mem.asBytes(&size));

        size = try binary.decode(u32, mem.asBytes(&size));
        if (size < @sizeOf(u32)) return error.MessageSizeTooSmall;
        if (size > 65536) return error.MessageSizeTooLarge;

        size -= @sizeOf(u32);

        while (buffer.count < size) {
            const num_bytes_read = try runtime.recv(&request, client.socket.fd, try buffer.writableWithSize(65536), 0);
            if (num_bytes_read == 0) return error.EndOfFile;
            buffer.update(num_bytes_read);
        }

        const message = try gpa.alloc(u8, size);
        defer gpa.free(message);

        try buffer.reader().readNoEof(message);

        const packet = try Packet.unmarshal(message);

        switch (packet.get(.type)) {
            .response => {
                if (self.rpc.unpark(RPC.Response{ .header = packet, .data = message[packet.buffer.len..] })) {
                    continue;
                }
            },
            else => {},
        }
    }
}

fn runWriteLoop(self: *Client, gpa: *mem.Allocator, conn: *Client.Connection, writer_done: *const bool) !void {
    const client = conn.client orelse unreachable;

    var buffer: [65536]u8 = undefined;
    var pos: usize = 0;

    var pending: std.SinglyLinkedList([]const u8) = .{};
    defer if (pending.first != null) {
        self.lock.acquire();
        defer self.lock.release();

        while (pending.popFirst()) |node| : (self.num_bytes_queued += node.data.len) {
            self.queue.prepend(node);
        }
    };

    var request: runtime.Request = .{};

    while (true) {
        self.lock.acquire();
        if (self.queue.first) |first| {
            self.queue.first = null;
            pending.first = first;

            self.num_bytes_queued = 0;
            self.pending.unparkWriteRequests();
        } else {
            if (self.closed or writer_done.*) {
                self.lock.release();
                return error.Closed;
            }

            conn.writer = .{
                .worker_id = runtime.getCurrentWorkerId(),
                .task = .{ .frame = @frame() },
            };

            suspend {
                self.pending.writers.append(&conn.writer);
                self.lock.release();
            }

            continue;
        }
        self.lock.release();

        var count: usize = 0;

        while (pending.popFirst()) |node| : (count += 1) {
            defer gpa.destroy(node);

            if (node.data.len >= buffer[pos..].len) {
                // If a queued message cannot fit into the buffer, do a dedicated send() on
                // the message rather than attempt to have it fit inside the buffer.

                if (node.data.len > buffer.len) {
                    @setCold(true);
                    try writeAll(&request, client, node.data);
                    continue;
                }

                try writeAll(&request, client, buffer[0..pos]);
                pos = 0;
            }

            mem.copy(u8, buffer[pos..], node.data);
            pos += node.data.len;
        }

        if (pos > 0) {
            try writeAll(&request, client, buffer[0..pos]);
            pos = 0;
        }
    }
}

fn connect(self: *Client) !tcp.Client {
    const worker_id = runtime.getCurrentWorkerId();

    self.connect_attempt.acquire();
    defer self.connect_attempt.release();

    if (self.circuit_breaker.tripped()) {
        return error.CircuitBreakerTripped;
    }

    if (self.circuit_breaker.hasFailuresReported()) {
        const attempts = self.circuit_breaker.getNumReportedFailures();
        const delay_max: i64 = 3000 * time.ns_per_ms;
        const delay_step: i64 = 10 * time.ns_per_ms;
        const delay = math.min(delay_max, delay_step * math.shl(i64, 1, attempts - 1));

        log.debug("{} [{}] reconnection attempt #{}: will retry in {} milliseconds", .{
            self.address,
            runtime.getCurrentWorkerId(),
            attempts,
            @divTrunc(delay, time.ns_per_ms),
        });

        runtime.yield(0);
        defer runtime.yield(worker_id);

        try runtime.timeout(&self.connect_backoff, .{ .nanoseconds = delay });
    }

    const client = try tcp.Client.init(.ip, .{ .close_on_exec = true, .nonblocking = true });
    errdefer client.deinit();

    try client.setNoDelay(true);

    var request: runtime.Request = .{};
    try runtime.connect(&request, client.socket.fd, self.address.into());

    return client;
}

fn writeAll(request: *runtime.Request, client: tcp.Client, buffer: []const u8) !void {
    var index: usize = 0;
    while (index < buffer.len) {
        index += try runtime.send(request, client.socket.fd, buffer[index..], os.MSG_NOSIGNAL);
    }
}

fn markReady(self: *Client, conn: *Client.Connection, client: tcp.Client) bool {
    self.lock.acquire();
    defer self.lock.release();

    if (self.closed) return false;

    log.debug("{} [{}] is connected and ready", .{ self.address, runtime.getCurrentWorkerId() });

    assert(conn.client == null);
    conn.client = client;

    self.circuit_breaker.reportSuccess();
    self.pending.reportConnectionResult(null);

    return true;
}

fn markError(self: *Client, err: anyerror) bool {
    self.lock.acquire();
    defer self.lock.release();

    log.debug("{} [{}] tried to connect and failed: {}", .{ self.address, runtime.getCurrentWorkerId(), err });

    self.circuit_breaker.reportFailure();
    if (self.pool.len > 1) return true;
    if (!self.closed and err != error.CircuitBreakerTripped) return false;

    log.debug("{} [{}] unparked coroutines waiting for a working connection reporting to them the error: {}", .{
        self.address,
        runtime.getCurrentWorkerId(),
        err,
    });

    self.pending.reportConnectionResult(err);

    return true;
}

fn markDisconnected(self: *Client, conn: *Client.Connection) bool {
    self.lock.acquire();
    defer self.lock.release();

    assert(conn.client != null);
    conn.client = null;

    return self.closed or self.pool.len > 1;
}

fn markClosed(self: *Client, conn: *Client.Connection) void {
    self.lock.acquire();
    defer self.lock.release();

    log.debug("{} [{}] was closed", .{ self.address, runtime.getCurrentWorkerId() });

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
