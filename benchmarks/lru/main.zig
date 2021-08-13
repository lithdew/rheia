const std = @import("std");
const lru = @import("../../lru.zig");

const assert = std.debug.assert;

pub const log_level = .debug;

const gpa = std.heap.raw_c_allocator;

pub fn main() !void {
    const log = std.log.scoped(.lru).info;

    const keys = try gpa.alloc(usize, 1_000_000);
    defer gpa.free(keys);

    var rng = std.rand.DefaultPrng.init(0);
    for (keys) |*key| key.* = rng.random.int(usize);

    var map = try lru.AutoHashMap(usize, usize, 50).initCapacity(gpa, 1 << 21);
    defer map.deinit(gpa);

    var timer = try std.time.Timer.start();
    for (keys) |key, i| {
        if (map.update(key, i) != .inserted) {
            return error.DuplicateKey;
        }
    }
    log("insert: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys) |key, i| {
        if (map.get(key) != i) {
            return error.NotFound;
        }
    }
    log("search: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys) |key, i| {
        if (map.delete(key) != i) {
            return error.NotFound;
        }
    }
    log("delete: {}", .{std.fmt.fmtDuration(timer.read())});

    log("put: {}, get: {}, del: {}", .{ map.put_probe_count, map.get_probe_count, map.del_probe_count });
}
