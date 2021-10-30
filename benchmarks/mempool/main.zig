const std = @import("std");

const c = @cImport({
    @cInclude("art.h");
    @cInclude("btree.h");
});

const rb = @import("rb.zig");
const rax = @import("rax.zig");
const art = @import("art.zig");
const hash_map = @import("../../hash_map.zig");
const skiplist = @import("skiplist.zig");
const art_travis = @import("art_travis.zig");

const assert = std.debug.assert;

pub const log_level = .debug;

const gpa = std.heap.raw_c_allocator;

pub fn main() !void {
    try benchmarkHashMap();
    try benchmarkBTree();
    try benchmarkRedBlackTree();
    try benchmarkBinaryHeap();
    try benchmarkSkipList();
    try benchmarkLibart();
    try benchmarkArtTravis();
    try benchmarkArt();
    try benchmarkRax();
}

fn benchmarkHashMap() !void {
    const log = std.log.scoped(.hash_map).info;

    const keys = try gpa.alloc([32]u8, 1_000_000);
    defer gpa.free(keys);

    var rng = std.rand.DefaultPrng.init(0);
    for (keys) |*key| {
        rng.random().bytes(key);
    }

    var map = try hash_map.HashMap(usize, 50).initCapacity(gpa, 1 << 21);
    defer map.deinit(gpa);

    var timer = try std.time.Timer.start();
    for (keys) |key, i| {
        try map.put(gpa, key, i);
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

fn benchmarkBTree() !void {
    const log = std.log.scoped(.btree).info;

    const keys = try gpa.alloc([32]u8, 1_000_000);
    defer gpa.free(keys);

    var rng = std.rand.DefaultPrng.init(0);
    for (keys) |*key| {
        rng.random().bytes(key);
    }

    const tree = c.btree_new(@sizeOf([32]u8), std.mem.page_size / @sizeOf([32:0]u8), compareBTreeHash, null);
    defer c.btree_free(tree);

    var timer = try std.time.Timer.start();
    for (keys) |*key| {
        if (c.btree_set(tree, key) != null) {
            return error.AlreadyExists;
        }
    }
    log("insert: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys) |*key| {
        if (c.btree_get(tree, key) == null) {
            return error.NotFound;
        }
    }
    log("search: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys) |*key| {
        if (c.btree_delete(tree, key) == null) {
            return error.NotFound;
        }
    }
    log("delete: {}", .{std.fmt.fmtDuration(timer.read())});
}

fn benchmarkRedBlackTree() !void {
    const log = std.log.scoped(.red_black_tree).info;

    const Node = struct {
        entry: rb.Node,
        key: [32]u8,
    };

    const nodes = try gpa.alloc(Node, 1_000_000);
    defer gpa.free(nodes);

    var rng = std.rand.DefaultPrng.init(0);
    for (nodes) |*node| {
        rng.random().bytes(&node.key);
    }

    var tree = rb.Tree.init(compareRedBlackHash);

    var timer = try std.time.Timer.start();
    for (nodes) |*node| {
        if (tree.insert(&node.entry) != null) {
            return error.AlreadyExists;
        }
    }
    log("insert: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (nodes) |*node| {
        if (tree.lookup(&node.entry) == null) {
            return error.NotFound;
        }
    }
    log("search: {}", .{std.fmt.fmtDuration(timer.read())});

    // timer.reset();
    // for (nodes) |*node| {
    //     tree.remove(&node.entry);
    // }
    // log("delete: {}", .{std.fmt.fmtDuration(timer.read())});

    log("skipping delete...", .{});
}

fn benchmarkBinaryHeap() !void {
    const log = std.log.scoped(.binary_heap).info;

    const keys = try gpa.alloc([32]u8, 1_000_000);
    defer gpa.free(keys);

    var rng = std.rand.DefaultPrng.init(0);
    for (keys) |*key| {
        rng.random().bytes(key);
    }

    var queue = std.PriorityQueue([32]u8).init(gpa, compareBinaryHeapHash);
    defer queue.deinit();

    var timer = try std.time.Timer.start();
    for (keys) |key| {
        try queue.add(key);
    }
    log("insert: {}", .{std.fmt.fmtDuration(timer.read())});

    log("skipping search/delete...", .{});
}

fn compareBTreeHash(a: ?*const c_void, b: ?*const c_void, _: ?*c_void) callconv(.C) c_int {
    return switch (std.mem.order(u8, @ptrCast(*const [32]u8, a.?), @ptrCast(*const [32]u8, b.?))) {
        .lt => -1,
        .eq => 0,
        .gt => 1,
    };
}

fn compareRedBlackHash(a: *rb.Node, b: *rb.Node, _: *rb.Tree) std.math.Order {
    const Node = struct {
        entry: rb.Node,
        key: [32]u8,
    };

    return std.mem.order(u8, &@fieldParentPtr(Node, "entry", a).key, &@fieldParentPtr(Node, "entry", b).key);
}

fn compareBinaryHeapHash(a: [32]u8, b: [32]u8) std.math.Order {
    return std.mem.order(u8, &a, &b);
}

fn benchmarkSkipList() !void {
    const log = std.log.scoped(.skiplist).info;

    const keys = try gpa.alloc([32]u8, 1_000_000);
    defer gpa.free(keys);

    var rng = std.rand.DefaultPrng.init(0);
    for (keys) |*key| {
        rng.random().bytes(key);
    }

    var list: skiplist.SkipList([32]u8) = .{};
    defer list.deinit(gpa);

    var timer = try std.time.Timer.start();
    for (keys) |key| {
        try list.insert(gpa, key);
    }
    log("insert: {}", .{std.fmt.fmtDuration(timer.read())});

    log("skipping search/delete...", .{});
}

fn benchmarkLibart() !void {
    const log = std.log.scoped(.libart).info;

    const keys = try gpa.alloc([32]u8, 1_000_000);
    defer gpa.free(keys);

    var rng = std.rand.DefaultPrng.init(0);
    for (keys) |*key| {
        rng.random().bytes(key);
    }

    var tree: c.art_tree = undefined;
    assert(c.art_tree_init(&tree) == 0);
    defer assert(c.art_tree_destroy(&tree) == 0);

    var timer = try std.time.Timer.start();
    for (keys) |*key| {
        if (c.art_insert(&tree, key, key.len, @intToPtr(*c_void, 0xdeadbeef)) != null) {
            return error.AlreadyExists;
        }
    }
    log("insert: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys) |*key| {
        if (c.art_search(&tree, key, key.len) == null) {
            return error.NotFound;
        }
    }
    log("search: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys) |*key| {
        if (c.art_delete(&tree, key, key.len) == null) {
            return error.NotFound;
        }
    }
    log("delete: {}", .{std.fmt.fmtDuration(timer.read())});
}

fn benchmarkArtTravis() !void {
    const log = std.log.scoped(.art_travis).info;

    const keys = try gpa.alloc([32:0]u8, 1_000_000);
    defer gpa.free(keys);

    var rng = std.rand.DefaultPrng.init(0);
    for (keys) |*key| {
        rng.random().bytes(key);
        key[32] = 0;
    }

    var tree = art_travis.Art(*c_void).init(gpa);
    defer tree.deinit();

    var timer = try std.time.Timer.start();
    for (keys) |*key| {
        const result = try tree.insert(key, @intToPtr(*c_void, 0xdeadbeef));
        if (result == .found) {
            return error.AlreadyExists;
        }
    }
    log("insert: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys) |*key| {
        if (tree.search(key) == .missing) {
            return error.NotFound;
        }
    }
    log("search: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys) |*key| {
        const result = try tree.delete(key);
        if (result == .missing) {
            return error.NotFound;
        }
    }
    log("delete: {}", .{std.fmt.fmtDuration(timer.read())});
}

fn benchmarkArt() !void {
    const log = std.log.scoped(.art).info;

    const keys = try gpa.alloc([32]u8, 1_000_000);
    defer gpa.free(keys);

    var rng = std.rand.DefaultPrng.init(0);
    for (keys) |*key| {
        rng.random().bytes(key);
    }

    var tree: art.Tree(*c_void) = .{};
    defer tree.deinit(gpa);

    var timer = try std.time.Timer.start();
    for (keys) |*key| {
        if ((try tree.insert(gpa, key, @intToPtr(*c_void, 0xdeadbeef))) != null) {
            return error.AlreadyExists;
        }
    }
    log("insert: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys) |*key| {
        if (tree.search(key) == null) {
            return error.NotFound;
        }
    }
    log("search: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys) |*key| {
        if (tree.delete(gpa, key) == null) {
            return error.NotFound;
        }
    }
    log("delete: {}", .{std.fmt.fmtDuration(timer.read())});
}

fn benchmarkRax() !void {
    const log = std.log.scoped(.rax).info;

    const keys = try gpa.alloc([32]u8, 1_000_000);
    defer gpa.free(keys);

    var rng = std.rand.DefaultPrng.init(0);
    for (keys) |*key| {
        rng.random().bytes(key);
    }

    var tree = try rax.Trie.init(gpa);
    defer tree.deinit(gpa);

    var timer = try std.time.Timer.start();
    for (keys) |*key| {
        if (!try tree.insert(gpa, key, @intToPtr(*c_void, 0xdeadbeef), .{})) {
            return error.AlreadyExists;
        }
    }
    log("insert: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys) |*key| {
        if (tree.find(key) == null) {
            return error.NotFound;
        }
    }
    log("search: {}", .{std.fmt.fmtDuration(timer.read())});

    timer.reset();
    for (keys) |*key| {
        if (!try tree.remove(gpa, key, null)) {
            return error.NotFound;
        }
    }
    log("delete: {}", .{std.fmt.fmtDuration(timer.read())});
}
