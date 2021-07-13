const std = @import("std");

const os = std.os;
const mem = std.mem;
const log = std.log.scoped(.client);

const ip = std.x.net.ip;
const tcp = std.x.net.tcp;
const testing = std.testing;

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
    writer: std.TailQueue(anyframe).Node,
};

address: ip.Address,

pool: []*Client.Connection,
capacity: usize,
next_worker_index: usize = 0,

queue: std.SinglyLinkedList([]const u8) = .{},
closed: bool = false,

pending: struct {
    connection_available: std.SinglyLinkedList(Client.Connection.Waiter) = .{},
    writes: std.TailQueue(anyframe) = .{},
    shutdown: std.SinglyLinkedList(anyframe) = .{},
} = .{},

pub fn init(gpa: *mem.Allocator, address: ip.Address) !Client {
    const capacity = 4;

    const pool = try gpa.alloc(*Client.Connection, capacity);
    errdefer gpa.free(pool);

    var pool_index: usize = 0;
    errdefer for (pool[0..pool_index]) |conn| gpa.destroy(conn);

    while (pool_index < capacity) : (pool_index += 1) {
        pool[pool_index] = try gpa.create(Client.Connection);
    }

    var client = Client{
        .address = address,
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

    for (self.pool) |conn| {
        if (conn.client) |*client| {
            client.shutdown(.recv) catch {};
            conn.client = null;
        }
    }

    while (self.pending.writes.popFirst()) |writer| {
        const conn = @fieldParentPtr(Client.Connection, "writer", writer);

        runtime.yield(0, conn.worker_index);
        defer runtime.yield(conn.worker_index, 0);

        resume writer.data;
    }
}

pub fn waitForShutdown(self: *Client) callconv(.Async) void {
    if (self.pool.len > 0) {
        var waiter: std.SinglyLinkedList(anyframe).Node = .{ .data = @frame() };
        suspend self.pending.shutdown.prepend(&waiter);
    }
}

pub fn write(self: *Client, runtime: *Runtime, message: []const u8) !void {
    try self.ensureConnectionAvailable(runtime);

    const node = try runtime.gpa.allocator.create(std.SinglyLinkedList([]const u8).Node);
    node.* = .{ .data = message };
    self.queue.prepend(node);

    if (self.pending.writes.popFirst()) |writer| {
        const conn = @fieldParentPtr(Client.Connection, "writer", writer);

        runtime.yield(0, conn.worker_index);
        defer runtime.yield(conn.worker_index, 0);

        resume writer.data;
    }
}

fn ensureConnectionAvailable(self: *Client, runtime: *Runtime) !void {
    if (self.closed) return error.Closed;

    if (self.pool.len == 0 or (self.queue.len() > 0 and self.pool.len < self.capacity)) {
        self.pool.len += 1;

        self.pool[self.pool.len - 1].worker_index = self.next_worker_index;
        self.next_worker_index = (self.next_worker_index + 1) % runtime.worker_count;

        log.info("{} [{}] is being spawned", .{ self.address, self.pool[self.pool.len - 1].worker_index });

        self.pool[self.pool.len - 1].client = null;
        self.pool[self.pool.len - 1].writer = .{ .data = undefined };
        self.pool[self.pool.len - 1].frame = async self.serve(runtime, self.pool[self.pool.len - 1]);
    }

    const connection_available = for (self.pool) |conn| {
        if (conn.client != null) break true;
    } else false;

    if (connection_available) return;

    var waiter: std.SinglyLinkedList(Client.Connection.Waiter).Node = .{ .data = .{ .frame = @frame() } };
    suspend self.pending.connection_available.prepend(&waiter);

    if (waiter.data.result) |result| {
        return result;
    }
}

fn serve(self: *Client, runtime: *Runtime, conn: *Client.Connection) void {
    defer {
        runtime.yield(conn.worker_index, 0);
        suspend self.markClosed(conn);
    }

    runtime.yield(0, conn.worker_index);

    const client = self.connect(runtime, conn, 1000) catch |err| {
        runtime.yield(conn.worker_index, 0);
        defer runtime.yield(0, conn.worker_index);
        return self.markError(conn, err);
    };
    defer client.deinit();

    const marked_ready = marked_ready: {
        runtime.yield(conn.worker_index, 0);
        defer runtime.yield(0, conn.worker_index);
        break :marked_ready self.markReady(conn, client);
    };

    if (!marked_ready) return;

    var read_frame = async self.runReadLoop(runtime, conn);
    var write_frame = async self.runWriteLoop(runtime, conn);

    _ = await read_frame;
    client.shutdown(.send) catch {};
    _ = await write_frame;
}

fn runReadLoop(_: *Client, runtime: *Runtime, conn: *Client.Connection) !void {
    var buffer: [256]u8 = undefined;

    while (conn.client) |client| {
        const num_bytes_read = runtime.io_workers.items[conn.worker_index].loop.recv(client.socket.fd, &buffer, 0) catch |err| return err;
        if (num_bytes_read == 0) break;
    }
}

fn runWriteLoop(self: *Client, runtime: *Runtime, conn: *Client.Connection) !void {
    var popped_nodes: std.SinglyLinkedList([]const u8) = .{};
    defer while (popped_nodes.popFirst()) |node| self.queue.prepend(node);

    while (conn.client) |client| {
        runtime.yield(conn.worker_index, 0);
        while (self.queue.popFirst()) |node| {
            popped_nodes.prepend(node);
        }
        if (popped_nodes.len() == 0) {
            suspend {
                conn.writer = .{ .data = @frame() };
                self.pending.writes.append(&conn.writer);
            }
            continue;
        }
        runtime.yield(0, conn.worker_index);

        while (popped_nodes.popFirst()) |node| {
            defer runtime.gpa.allocator.destroy(node);

            var index: usize = 0;
            while (index < node.data.len) {
                index += try runtime.io_workers.items[conn.worker_index].loop.send(client.socket.fd, node.data[index..], os.MSG_NOSIGNAL);
            }
        }
    }
}

fn connect(self: *Client, runtime: *Runtime, conn: *Client.Connection, timeout_milliseconds: u32) !tcp.Client {
    const client = try tcp.Client.init(.ip, .{ .close_on_exec = true });
    errdefer client.deinit();

    try client.setWriteTimeout(timeout_milliseconds);
    try runtime.io_workers.items[conn.worker_index].loop.connect(client.socket.fd, self.address.into());

    return client;
}

fn markReady(self: *Client, conn: *Client.Connection, client: tcp.Client) bool {
    if (self.closed) return false;

    conn.client = client;

    while (self.pending.connection_available.popFirst()) |node| {
        resume node.data.frame;
    }

    log.debug("{} [{}] is connected and ready", .{ self.address, conn.worker_index });

    return true;
}

fn markError(self: *Client, conn: *Client.Connection, err: anyerror) void {
    log.debug("{} [{}] reported an error: {}", .{ self.address, conn.worker_index, err });

    while (self.pending.connection_available.popFirst()) |node| {
        node.data.result = err;
        resume node.data.frame;
    }
}

fn markClosed(self: *Client, conn: *Client.Connection) void {
    conn.client = null;

    const i = mem.indexOfScalar(*Client.Connection, self.pool, conn) orelse unreachable;
    log.debug("{} [{}] was closed", .{ self.address, conn.worker_index });

    defer {
        self.pool.len -= 1;
        if (self.pool.len == 0) {
            while (self.pending.shutdown.popFirst()) |node| {
                resume node.data;
            }
        }
    }

    if (i == self.pool.len - 1) return;
    mem.swap(*Client.Connection, &self.pool[i], &self.pool[self.pool.len - 1]);
}

test {
    testing.refAllDecls(@This());
}
