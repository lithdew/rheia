const std = @import("std");

const mem = std.mem;
const math = std.math;
const testing = std.testing;

const assert = std.debug.assert;

pub fn AutoHashMap(comptime K: type, comptime V: type, comptime max_load_percentage: comptime_int) type {
    return HashMap(K, V, max_load_percentage, std.hash_map.AutoContext(K));
}

pub fn HashMap(comptime K: type, comptime V: type, comptime max_load_percentage: comptime_int, comptime Context: type) type {
    return struct {
        pub const Entry = struct {
            key: K = undefined,
            value: V = undefined,
            prev: ?*Entry = null,
            next: ?*Entry = null,

            pub fn isEmpty(self: *const Entry, map: *const Self) bool {
                return map.len == 0 or (map.head != self and self.prev == null and self.next == null);
            }

            pub fn format(self: *const Entry, comptime layout: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
                _ = layout;
                _ = options;
                try std.fmt.format(writer, "{*} (key: {}, value: {}, prev: {*}, next: {*})", .{
                    self,
                    self.key,
                    self.value,
                    self.prev,
                    self.next,
                });
            }
        };

        pub const KV = struct {
            key: K,
            value: V,
        };

        const Self = @This();

        entries: [*]Entry,
        len: usize = 0,
        shift: u6,

        head: ?*Entry = null,
        tail: ?*Entry = null,

        put_probe_count: usize = 0,
        get_probe_count: usize = 0,
        del_probe_count: usize = 0,

        pub fn initCapacity(gpa: *mem.Allocator, capacity: u64) !Self {
            assert(math.isPowerOfTwo(capacity));

            const shift = 63 - math.log2_int(u64, capacity) + 1;
            const overflow = capacity / 10 + (63 - @as(u64, shift) + 1) << 1;

            const entries = try gpa.alloc(Entry, @intCast(usize, capacity + overflow));
            mem.set(Entry, entries, .{});

            return Self{
                .entries = entries.ptr,
                .shift = shift,
            };
        }

        pub fn deinit(self: *Self, gpa: *mem.Allocator) void {
            gpa.free(self.slice());
        }

        pub fn clear(self: *Self) void {
            mem.set(Entry, self.slice(), .{});
            self.len = 0;
            self.head = null;
            self.tail = null;
        }

        pub fn slice(self: *Self) []Entry {
            const capacity = @as(u64, 1) << (63 - self.shift + 1);
            const overflow = capacity / 10 + (63 - @as(usize, self.shift) + 1) << 1;
            return self.entries[0..@intCast(usize, capacity + overflow)];
        }

        pub const UpdateResult = union(enum) {
            evicted: KV,
            updated: V,
            inserted,
        };

        pub fn update(self: *Self, key: K, value: V) UpdateResult {
            if (@sizeOf(Context) != 0) {
                @compileError("updateContext must be used.");
            }
            return self.updateContext(key, value, undefined);
        }

        pub fn updateContext(self: *Self, key: K, value: V, ctx: Context) UpdateResult {
            const result = self.getOrPutContext(key, ctx);
            if (result.found_existing) {
                const old_value = result.value_ptr.*;
                result.value_ptr.* = value;
                return .{ .updated = old_value };
            }

            result.value_ptr.* = value;

            if (self.len > (@as(u64, 1) << (63 - self.shift + 1)) * max_load_percentage / 100) {
                return .{ .evicted = self.popOrNullContext(ctx).? };
            }
            return .inserted;
        }

        pub const GetOrPutResult = struct {
            value_ptr: *V,
            found_existing: bool,
        };

        pub fn getOrPut(self: *Self, key: K) GetOrPutResult {
            if (@sizeOf(Context) != 0) {
                @compileError("getOrPutContext must be used.");
            }
            return self.getOrPutContext(key, undefined);
        }

        pub fn getOrPutContext(self: *Self, key: K, ctx: Context) GetOrPutResult {
            var it: Entry = .{ .key = key, .value = undefined };
            var i = ctx.hash(key) >> self.shift;

            var inserted_at: ?usize = null;
            while (true) : (i += 1) {
                if (self.entries[i].isEmpty(self)) {
                    if (inserted_at == null) {
                        self.prependNode(&it, &self.entries[i]);
                    } else {
                        self.readjustNodePointers(&it, &self.entries[i]);
                    }
                    self.entries[i] = it;
                    self.len += 1;
                    return .{
                        .value_ptr = &self.entries[inserted_at orelse i].value,
                        .found_existing = false,
                    };
                } else if (ctx.hash(self.entries[i].key) > ctx.hash(it.key)) {
                    if (inserted_at == null) {
                        self.prependNode(&it, &self.entries[i]);
                        inserted_at = i;
                    } else {
                        self.readjustNodePointers(&it, &self.entries[i]);
                    }
                    mem.swap(Entry, &it, &self.entries[i]);
                } else if (ctx.eql(self.entries[i].key, key)) {
                    self.removeNode(&self.entries[i]);
                    self.prependNode(&it, &self.entries[i]);
                    self.entries[i].prev = it.prev;
                    self.entries[i].next = it.next;
                    return .{
                        .value_ptr = &self.entries[i].value,
                        .found_existing = true,
                    };
                }
                self.put_probe_count += 1;
            }
        }

        pub fn get(self: *Self, key: K) ?V {
            if (@sizeOf(Context) != 0) {
                @compileError("getContext must be used.");
            }
            return self.getContext(key, undefined);
        }

        pub fn getContext(self: *Self, key: K, ctx: Context) ?V {
            const hash = ctx.hash(key);

            var i = hash >> self.shift;
            while (true) : (i += 1) {
                const entry = &self.entries[i];
                if (entry.isEmpty(self) or ctx.hash(entry.key) > hash) {
                    return null;
                } else if (ctx.eql(entry.key, key)) {
                    return entry.value;
                }
                self.get_probe_count += 1;
            }
        }

        pub fn delete(self: *Self, key: K) ?V {
            if (@sizeOf(Context) != 0) {
                @compileError("deleteContext must be used.");
            }
            return self.deleteContext(key, undefined);
        }

        pub fn deleteContext(self: *Self, key: K, ctx: Context) ?V {
            const hash = ctx.hash(key);

            var i = hash >> self.shift;
            while (true) : (i += 1) {
                const entry = &self.entries[i];
                if (entry.isEmpty(self) or ctx.hash(entry.key) > hash) {
                    return null;
                } else if (ctx.eql(entry.key, key)) {
                    break;
                }
                self.del_probe_count += 1;
            }

            return self.deleteEntryAtIndex(i, ctx);
        }

        pub fn moveEntryToFront(self: *Self, entry: *Entry) void {
            self.removeNode(entry);
            self.prependNode(entry, entry);
        }

        pub fn popOrNull(self: *Self) ?KV {
            if (@sizeOf(Context) != 0) {
                @compileError("popOrNullContext must be used.");
            }
            return self.popOrNullContext(undefined);
        }

        pub fn popOrNullContext(self: *Self, ctx: Context) ?KV {
            const tail = self.tail orelse return null;
            const tail_index = (@ptrToInt(tail) - @ptrToInt(self.entries)) / @sizeOf(Entry);
            return KV{ .key = tail.key, .value = self.deleteEntryAtIndex(tail_index, ctx) };
        }

        fn deleteEntryAtIndex(self: *Self, i_const: usize, ctx: Context) V {
            const value = self.entries[i_const].value;
            self.removeNode(&self.entries[i_const]);

            var i = i_const;
            while (true) : (i += 1) {
                const j = ctx.hash(self.entries[i + 1].key) >> self.shift;
                if (i < j or self.entries[i + 1].isEmpty(self)) {
                    break;
                }
                self.entries[i] = self.entries[i + 1];
                self.readjustNodePointers(&self.entries[i], &self.entries[i]);
                self.del_probe_count += 1;
            }

            self.entries[i] = .{};
            self.len -= 1;

            return value;
        }

        /// Prepend entry to head of linked list, or fix up the entry's linked list pointers.
        fn prependNode(self: *Self, it: *Entry, entry: *Entry) void {
            it.next = self.head;
            if (self.head) |head| {
                head.prev = entry;
            } else {
                self.tail = entry;
            }
            self.head = entry;
        }

        /// Remove entry from the linked list.
        fn removeNode(self: *Self, entry: *Entry) void {
            if (entry.prev) |prev| {
                prev.next = entry.next;
            } else {
                self.head = entry.next;
            }
            if (entry.next) |next| {
                next.prev = entry.prev;
            } else {
                self.tail = entry.prev;
            }
            entry.next = null;
            entry.prev = null;
        }

        /// Re-adjust entry's linked list pointers.
        fn readjustNodePointers(self: *Self, it: *Entry, entry: *Entry) void {
            if (it.prev) |prev| {
                prev.next = entry;
            } else {
                self.head = entry;
            }
            if (it.next) |next| {
                next.prev = entry;
            } else {
                self.tail = entry;
            }
        }
    };
}

test "lru.HashMap: eviction on insert" {
    const Cache = AutoHashMap(usize, usize, 100);

    var map = try Cache.initCapacity(testing.allocator, 4);
    defer map.deinit(testing.allocator);

    var i: usize = 0;
    while (i < 4) : (i += 1) {
        try testing.expectEqual(Cache.UpdateResult.inserted, map.update(i, i));
    }

    while (i < 8) : (i += 1) {
        const evicted = map.update(i, i).evicted;
        try testing.expectEqual(i - 4, evicted.key);
        try testing.expectEqual(i - 4, evicted.value);
    }

    try testing.expectEqual(@as(usize, 4), map.len);

    try testing.expectEqual(@as(usize, 7), map.head.?.key);
    try testing.expectEqual(@as(usize, 7), map.head.?.value);

    try testing.expectEqual(@as(usize, 4), map.tail.?.key);
    try testing.expectEqual(@as(usize, 4), map.tail.?.value);

    var it = map.head;
    while (it) |node| : (it = node.next) {
        try testing.expectEqual(i - 1, node.key);
        try testing.expectEqual(i - 1, node.value);
        i -= 1;
    }

    while (i < 8) : (i += 1) {
        try testing.expectEqual(i, map.delete(i).?);
    }
    try testing.expectEqual(@as(usize, 0), map.len);
    try testing.expectEqual(@as(?*Cache.Entry, null), map.head);
    try testing.expectEqual(@as(?*Cache.Entry, null), map.tail);
}

test "lru.HashMap: update, get, delete without eviction" {
    const Cache = AutoHashMap(usize, usize, 100);

    var seed: usize = 0;
    while (seed < 10_000) : (seed += 1) {
        var rng = std.rand.DefaultPrng.init(seed);

        const keys = try testing.allocator.alloc(usize, 128);
        defer testing.allocator.free(keys);

        for (keys) |*key| key.* = rng.random.int(usize);

        var map = try Cache.initCapacity(testing.allocator, 128);
        defer map.deinit(testing.allocator);

        // add all entries

        for (keys) |key, i| try testing.expectEqual(Cache.UpdateResult.inserted, map.update(key, i));
        for (keys) |key, i| try testing.expectEqual(i, map.get(key).?);
        try testing.expectEqual(keys.len, map.len);

        try testing.expectEqual(keys[keys.len - 1], map.head.?.key);
        try testing.expectEqual(keys.len - 1, map.head.?.value);

        try testing.expectEqual(keys[0], map.tail.?.key);
        try testing.expectEqual(@as(usize, 0), map.tail.?.value);

        // randomly promote half of all entries to head except tail

        var key_index: usize = 0;
        while (key_index < keys.len / 2) : (key_index += 1) {
            const index = rng.random.intRangeAtMost(usize, 1, keys.len - 1);
            try testing.expectEqual(Cache.UpdateResult.updated, map.update(keys[index], index));

            try testing.expectEqual(keys[index], map.head.?.key);
            try testing.expectEqual(index, map.head.?.value);

            try testing.expectEqual(keys[0], map.tail.?.key);
            try testing.expectEqual(@as(usize, 0), map.tail.?.value);
        }

        // promote tail to head

        const expected = map.tail.?.prev.?;

        try testing.expectEqual(Cache.UpdateResult.updated, map.update(keys[0], 0));
        for (keys) |key, i| try testing.expectEqual(i, map.get(key).?);
        try testing.expectEqual(keys.len, map.len);

        try testing.expectEqual(keys[0], map.head.?.key);
        try testing.expectEqual(@as(usize, 0), map.head.?.value);

        try testing.expectEqual(expected.key, map.tail.?.key);
        try testing.expectEqual(expected.value, map.tail.?.value);

        // delete all entries

        for (keys) |key, i| try testing.expectEqual(i, map.delete(key).?);
        try testing.expectEqual(@as(usize, 0), map.len);
        try testing.expectEqual(@as(?*Cache.Entry, null), map.head);
        try testing.expectEqual(@as(?*Cache.Entry, null), map.tail);
    }
}
