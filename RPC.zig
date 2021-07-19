const std = @import("std");

const mem = std.mem;
const math = std.math;
const testing = std.testing;

const assert = std.debug.assert;

const Lock = @import("Lock.zig");
const Worker = @import("Worker.zig");
const Packet = @import("Packet.zig");
const Runtime = @import("Runtime.zig");

const RPC = @This();

pub const max_num_pending_entries = 65536;

pub const Waiter = struct {
    worker_id: usize,
    task: Worker.Task,
    result: ?struct {
        header: Packet,
        data: []const u8,
    } = null,
};

lock: Lock = .{},
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

pub fn shutdown(self: *RPC, runtime: *Runtime) void {
    self.lock.acquire();
    defer self.lock.release(runtime);

    for (self.entries) |*maybe_waiter| {
        if (maybe_waiter.*) |waiter| {
            maybe_waiter.* = null;
            runtime.scheduleTo(waiter.worker_id, &waiter.task);
        }
    }
}

pub fn park(self: *RPC, runtime: *Runtime, waiter: *RPC.Waiter) !u32 {
    self.lock.acquire();
    defer self.lock.release(runtime);

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
    defer self.lock.release(runtime);

    const distance = nonce -% self.tail;
    if (distance >= self.entries.len) return null;

    const index = nonce & (self.entries.len - 1);
    const waiter = self.entries[index] orelse return null;
    self.entries[index] = null;

    return waiter;
}

pub fn unpark(self: *RPC, runtime: *Runtime, packet: Packet, data: []const u8) bool {
    self.lock.acquire();
    defer self.lock.release(runtime);

    const nonce = packet.get(.nonce);

    const distance = nonce -% self.tail;
    if (distance >= self.entries.len) return false;

    const index = nonce & (self.entries.len - 1);
    const waiter = self.entries[index] orelse return false;
    self.entries[index] = null;

    if (distance == 0) self.tail +%= 1;

    waiter.result = .{ .header = packet, .data = data };
    runtime.scheduleTo(waiter.worker_id, &waiter.task);

    return true;
}

test {
    testing.refAllDecls(@This());
}
