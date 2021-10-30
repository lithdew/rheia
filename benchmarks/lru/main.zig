const std = @import("std");
const lru = @import("../../lru.zig");

const assert = std.debug.assert;

pub const log_level = .debug;

const gpa = std.heap.raw_c_allocator;

pub fn main() !void {
    try benchmarkListSmall();
    try benchmarkIntrusiveSmall();
    try benchmarkListSmallFull();
    try benchmarkIntrusiveSmallFull();
    try benchmarkList();
    try benchmarkIntrusive();
    try benchmarkListFull();
    try benchmarkIntrusiveFull();
}

pub fn benchmarkListSmall() !void {
    const log = std.log.scoped(.@"linked-list lru w/ load factor 50% (4096 elements)").info;

    const keys = try gpa.alloc(usize, 1 << 12);
    defer gpa.free(keys);

    var rng = std.rand.DefaultPrng.init(0);
    for (keys) |*key| key.* = rng.random().int(usize);

    var map = try lru.AutoHashMap(usize, usize, 50).initCapacity(gpa, 1 << 13);
    defer map.deinit(gpa);

    var timer = try std.time.Timer.start();
    for (keys) |key, i| {
        const result = map.getOrPut(key);
        if (result.found_existing) return error.DuplicateKey;
        result.node.value = i;
        map.moveToFront(result.node);
    }
    log("insert: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys) |key, i| {
        const result = map.get(key) orelse return error.NotFound;
        if (result.value != i) return error.UnexpectedValue;
    }
    log("search: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys) |key, i| {
        const result = map.delete(key) orelse return error.NotFound;
        if (result.value != i) return error.UnexpectedValue;
    }
    log("delete: {}", .{std.fmt.fmtDuration(timer.read())});

    log("put: {}, get: {}, del: {}", .{ map.put_probe_count, map.get_probe_count, map.del_probe_count });
}

pub fn benchmarkIntrusiveSmall() !void {
    const log = std.log.scoped(.@"intrusive lru w/ load factor 50% (4096 elements)").info;

    const keys = try gpa.alloc(usize, 1 << 12);
    defer gpa.free(keys);

    var rng = std.rand.DefaultPrng.init(0);
    for (keys) |*key| key.* = rng.random().int(usize);

    var map = try lru.AutoIntrusiveHashMap(usize, usize, 50).initCapacity(gpa, 1 << 13);
    defer map.deinit(gpa);

    var timer = try std.time.Timer.start();
    for (keys) |key, i| {
        const result = map.update(key, i);
        if (result == .updated) {
            return error.DuplicateKey;
        }
    }
    log("insert: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys) |key, i| {
        const result = map.get(key) orelse return error.NotFound;
        if (result.value != i) return error.UnexpectedValue;
    }
    log("search: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys) |key, i| {
        const value = map.delete(key) orelse return error.NotFound;
        if (value != i) return error.UnexpectedValue;
    }
    log("delete: {}", .{std.fmt.fmtDuration(timer.read())});

    log("put: {}, get: {}, del: {}", .{ map.put_probe_count, map.get_probe_count, map.del_probe_count });
}

pub fn benchmarkListSmallFull() !void {
    const log = std.log.scoped(.@"linked-list lru w/ load factor 100% (4096 elements)").info;

    const keys = try gpa.alloc(usize, 1 << 12);
    defer gpa.free(keys);

    var rng = std.rand.DefaultPrng.init(0);
    for (keys) |*key| key.* = rng.random().int(usize);

    var map = try lru.AutoHashMap(usize, usize, 50).initCapacity(gpa, 1 << 12);
    defer map.deinit(gpa);

    var timer = try std.time.Timer.start();
    for (keys) |key, i| {
        const result = map.getOrPut(key);
        if (result.found_existing) return error.DuplicateKey;
        result.node.value = i;
        map.moveToFront(result.node);
    }
    log("insert: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys[keys.len / 2 ..]) |key, i| {
        const result = map.get(key) orelse return error.NotFound;
        if (result.value != i + keys.len / 2) return error.UnexpectedValue;
    }
    log("search: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys[keys.len / 2 ..]) |key, i| {
        const result = map.delete(key) orelse return error.NotFound;
        if (result.value != i + keys.len / 2) return error.UnexpectedValue;
    }
    log("delete: {}", .{std.fmt.fmtDuration(timer.read())});

    log("put: {}, get: {}, del: {}", .{ map.put_probe_count, map.get_probe_count, map.del_probe_count });
}

pub fn benchmarkIntrusiveSmallFull() !void {
    const log = std.log.scoped(.@"intrusive lru w/ load factor 100% (4096 elements)").info;

    const keys = try gpa.alloc(usize, 1 << 12);
    defer gpa.free(keys);

    var rng = std.rand.DefaultPrng.init(0);
    for (keys) |*key| key.* = rng.random().int(usize);

    var map = try lru.AutoIntrusiveHashMap(usize, usize, 50).initCapacity(gpa, 1 << 12);
    defer map.deinit(gpa);

    var timer = try std.time.Timer.start();
    for (keys) |key, i| {
        const result = map.update(key, i);
        if (result == .updated) {
            return error.DuplicateKey;
        }
    }
    log("insert: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys[keys.len / 2 ..]) |key, i| {
        const result = map.get(key) orelse return error.NotFound;
        if (result.value != i + keys.len / 2) return error.UnexpectedValue;
    }
    log("search: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys[keys.len / 2 ..]) |key, i| {
        const value = map.delete(key) orelse return error.NotFound;
        if (value != i + keys.len / 2) return error.UnexpectedValue;
    }
    log("delete: {}", .{std.fmt.fmtDuration(timer.read())});

    log("put: {}, get: {}, del: {}", .{ map.put_probe_count, map.get_probe_count, map.del_probe_count });
}

pub fn benchmarkList() !void {
    const log = std.log.scoped(.@"linked-list lru w/ load factor 50% (1 million elements)").info;

    const keys = try gpa.alloc(usize, 1_000_000);
    defer gpa.free(keys);

    var rng = std.rand.DefaultPrng.init(0);
    for (keys) |*key| key.* = rng.random().int(usize);

    var map = try lru.AutoHashMap(usize, usize, 50).initCapacity(gpa, 1 << 21);
    defer map.deinit(gpa);

    var timer = try std.time.Timer.start();
    for (keys) |key, i| {
        const result = map.getOrPut(key);
        if (result.found_existing) return error.DuplicateKey;
        result.node.value = i;
        map.moveToFront(result.node);
    }
    log("insert: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys) |key, i| {
        const result = map.get(key) orelse return error.NotFound;
        if (result.value != i) return error.UnexpectedValue;
    }
    log("search: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys) |key, i| {
        const result = map.delete(key) orelse return error.NotFound;
        if (result.value != i) return error.UnexpectedValue;
    }
    log("delete: {}", .{std.fmt.fmtDuration(timer.read())});

    log("put: {}, get: {}, del: {}", .{ map.put_probe_count, map.get_probe_count, map.del_probe_count });
}

pub fn benchmarkIntrusive() !void {
    const log = std.log.scoped(.@"intrusive lru w/ load factor 50% (1 million elements)").info;

    const keys = try gpa.alloc(usize, 1_000_000);
    defer gpa.free(keys);

    var rng = std.rand.DefaultPrng.init(0);
    for (keys) |*key| key.* = rng.random().int(usize);

    var map = try lru.AutoIntrusiveHashMap(usize, usize, 50).initCapacity(gpa, 1 << 21);
    defer map.deinit(gpa);

    var timer = try std.time.Timer.start();
    for (keys) |key, i| {
        const result = map.update(key, i);
        if (result == .updated) {
            return error.DuplicateKey;
        }
    }
    log("insert: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys) |key, i| {
        const result = map.get(key) orelse return error.NotFound;
        if (result.value != i) return error.UnexpectedValue;
    }
    log("search: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys) |key, i| {
        const value = map.delete(key) orelse return error.NotFound;
        if (value != i) return error.UnexpectedValue;
    }
    log("delete: {}", .{std.fmt.fmtDuration(timer.read())});

    log("put: {}, get: {}, del: {}", .{ map.put_probe_count, map.get_probe_count, map.del_probe_count });
}

pub fn benchmarkListFull() !void {
    const log = std.log.scoped(.@"linked-list lru w/ load factor 100% (1 million elements)").info;

    const keys = try gpa.alloc(usize, 1_000_000);
    defer gpa.free(keys);

    var rng = std.rand.DefaultPrng.init(0);
    for (keys) |*key| key.* = rng.random().int(usize);

    var map = try lru.AutoHashMap(usize, usize, 50).initCapacity(gpa, 1 << 20);
    defer map.deinit(gpa);

    var timer = try std.time.Timer.start();
    for (keys) |key, i| {
        const result = map.getOrPut(key);
        if (result.found_existing) return error.DuplicateKey;
        result.node.value = i;
        map.moveToFront(result.node);
    }
    log("insert: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys[keys.len / 2 ..]) |key, i| {
        const result = map.get(key) orelse return error.NotFound;
        if (result.value != i + keys.len / 2) return error.UnexpectedValue;
    }
    log("search: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys[keys.len / 2 ..]) |key, i| {
        const result = map.delete(key) orelse return error.NotFound;
        if (result.value != i + keys.len / 2) return error.UnexpectedValue;
    }
    log("delete: {}", .{std.fmt.fmtDuration(timer.read())});

    log("put: {}, get: {}, del: {}", .{ map.put_probe_count, map.get_probe_count, map.del_probe_count });
}

pub fn benchmarkIntrusiveFull() !void {
    const log = std.log.scoped(.@"intrusive lru w/ load factor 100% (1 million elements)").info;

    const keys = try gpa.alloc(usize, 1_000_000);
    defer gpa.free(keys);

    var rng = std.rand.DefaultPrng.init(0);
    for (keys) |*key| key.* = rng.random().int(usize);

    var map = try lru.AutoIntrusiveHashMap(usize, usize, 50).initCapacity(gpa, 1 << 20);
    defer map.deinit(gpa);

    var timer = try std.time.Timer.start();
    for (keys) |key, i| {
        const result = map.update(key, i);
        if (result == .updated) {
            return error.DuplicateKey;
        }
    }
    log("insert: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys[keys.len / 2 ..]) |key, i| {
        const result = map.get(key) orelse return error.NotFound;
        if (result.value != i + keys.len / 2) return error.UnexpectedValue;
    }
    log("search: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys[keys.len / 2 ..]) |key, i| {
        const value = map.delete(key) orelse return error.NotFound;
        if (value != i + keys.len / 2) return error.UnexpectedValue;
    }
    log("delete: {}", .{std.fmt.fmtDuration(timer.read())});

    log("put: {}, get: {}, del: {}", .{ map.put_probe_count, map.get_probe_count, map.del_probe_count });
}
