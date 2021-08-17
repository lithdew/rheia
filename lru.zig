const std = @import("std");

const mem = std.mem;
const math = std.math;
const testing = std.testing;

const SinglyLinkedList = @import("intrusive.zig").SinglyLinkedList;
const DoublyLinkedDeque = @import("intrusive.zig").DoublyLinkedDeque;

const assert = std.debug.assert;

pub fn AutoHashMap(
    comptime K: type,
    comptime V: type,
    comptime max_load_percentage: comptime_int,
) type {
    return HashMap(K, V, max_load_percentage, std.hash_map.AutoContext(K));
}

pub fn HashMap(
    comptime K: type,
    comptime V: type,
    comptime max_load_percentage: comptime_int,
    comptime Context: type,
) type {
    return struct {
        pub const Entry = struct {
            key: K = undefined,
            value: V = undefined,
            prev: ?*Entry = null,
            next: ?*Entry = null,
        };

        const Self = @This();

        entries: [*]?*Entry,
        nodes: [*]Entry,

        len: usize = 0,
        shift: u6,

        free: SinglyLinkedList(Entry, .next),
        live: DoublyLinkedDeque(Entry, .next, .prev) = .{},

        put_probe_count: usize = 0,
        get_probe_count: usize = 0,
        del_probe_count: usize = 0,

        pub fn initCapacity(gpa: *mem.Allocator, capacity: u64) !Self {
            assert(math.isPowerOfTwo(capacity));

            const shift = 63 - math.log2_int(u64, capacity) + 1;
            const overflow = capacity / 10 + (63 - @as(u64, shift) + 1) << 1;

            const entries = try gpa.alloc(?*Entry, @intCast(usize, capacity + overflow));
            errdefer gpa.free(entries);

            const nodes = try gpa.alloc(Entry, @intCast(usize, capacity * max_load_percentage / 100));
            errdefer gpa.free(nodes);

            mem.set(?*Entry, entries, null);
            mem.set(Entry, nodes, .{});

            var free: SinglyLinkedList(Entry, .next) = .{};
            for (nodes) |*node| free.prepend(node);

            return Self{
                .entries = entries.ptr,
                .nodes = nodes.ptr,
                .shift = shift,
                .free = free,
            };
        }

        pub fn deinit(self: *Self, gpa: *mem.Allocator) void {
            const capacity = @as(u64, 1) << (63 - self.shift + 1);
            const overflow = capacity / 10 + (63 - @as(usize, self.shift) + 1) << 1;
            gpa.free(self.entries[0..@intCast(usize, capacity + overflow)]);
            gpa.free(self.nodes[0..@intCast(usize, capacity * max_load_percentage / 100)]);
        }

        pub fn clear(self: *Self) void {
            const capacity = @as(u64, 1) << (63 - self.shift + 1);
            const overflow = capacity / 10 + (63 - @as(usize, self.shift) + 1) << 1;
            mem.set(?*Entry, self.entries[0..@intCast(usize, capacity + overflow)], null);
            mem.set(Entry, self.nodes[0..@intCast(usize, capacity * max_load_percentage / 100)], .{});
            self.len = 0;
        }

        pub fn slice(self: *Self) []?*Entry {
            const capacity = @as(u64, 1) << (63 - self.shift + 1);
            const overflow = capacity / 10 + (63 - @as(usize, self.shift) + 1) << 1;
            return self.entries[0..@intCast(usize, capacity + overflow)];
        }

        pub const KV = struct {
            key: K,
            value: V,
        };

        pub const GetOrPutResult = struct {
            evicted: ?KV,
            node: *Entry,
            found_existing: bool,
        };

        pub fn getOrPut(self: *Self, key: K) GetOrPutResult {
            if (@sizeOf(Context) != 0) {
                @compileError("getOrPutContext must be used.");
            }
            return self.getOrPutContext(key, undefined);
        }

        pub fn getOrPutContext(self: *Self, key: K, ctx: Context) GetOrPutResult {
            var it: ?*Entry = null;
            var i = ctx.hash(key) >> self.shift;

            var inserted_at: ?usize = null;
            while (true) : (i += 1) {
                const entry = self.entries[i] orelse {
                    self.entries[i] = it;

                    if (self.free.popFirst()) |node| {
                        node.key = key;
                        self.entries[inserted_at orelse i] = node;
                        self.len += 1;

                        return .{
                            .evicted = null,
                            .node = node,
                            .found_existing = false,
                        };
                    } else {
                        const tail = self.live.tail.?;

                        const evicted: KV = .{
                            .key = tail.key,
                            .value = tail.value,
                        };

                        self.entries[inserted_at orelse i] = &Entry{ .key = key };
                        const tail_index = self.getIndex(tail.key).?;
                        self.entries[inserted_at orelse i] = tail;

                        self.shiftBackwardsContext(tail_index, ctx);

                        tail.key = key;
                        tail.value = undefined;

                        return .{
                            .evicted = evicted,
                            .node = tail,
                            .found_existing = false,
                        };
                    }
                };
                if (ctx.hash(entry.key) > ctx.hash(if (it) |node| node.key else key)) {
                    self.entries[i] = it;
                    if (inserted_at == null) {
                        inserted_at = i;
                    }
                    it = entry;
                } else if (ctx.eql(entry.key, key)) {
                    return .{
                        .evicted = null,
                        .node = entry,
                        .found_existing = true,
                    };
                }
                self.put_probe_count += 1;
            }
        }

        pub fn getIndex(self: *Self, key: K) ?usize {
            if (@sizeOf(Context) != 0) {
                @compileError("getContext must be used.");
            }
            return self.getIndexContext(key, undefined);
        }

        pub fn getIndexContext(self: *Self, key: K, ctx: Context) ?usize {
            const hash = ctx.hash(key);

            var i = hash >> self.shift;
            while (true) : (i += 1) {
                const entry = self.entries[i] orelse return null;
                if (ctx.hash(entry.key) > hash) return null;
                if (ctx.eql(entry.key, key)) return i;
                self.get_probe_count += 1;
            }
        }

        pub fn get(self: *Self, key: K) ?*Entry {
            if (@sizeOf(Context) != 0) {
                @compileError("getContext must be used.");
            }
            return self.getContext(key, undefined);
        }

        pub fn getContext(self: *Self, key: K, ctx: Context) ?*Entry {
            const hash = ctx.hash(key);

            var i = hash >> self.shift;
            while (true) : (i += 1) {
                const entry = self.entries[i] orelse return null;
                if (ctx.hash(entry.key) > hash) return null;
                if (ctx.eql(entry.key, key)) return entry;
                self.get_probe_count += 1;
            }
        }

        pub fn moveToFront(self: *Self, node: *Entry) void {
            _ = self.live.remove(node);
            self.live.prepend(node);
        }

        pub fn moveToBack(self: *Self, node: *Entry) void {
            _ = self.live.remove(node);
            self.live.append(node);
        }

        pub fn delete(self: *Self, key: K) ?KV {
            if (@sizeOf(Context) != 0) {
                @compileError("deleteContext must be used.");
            }
            return self.deleteContext(key, undefined);
        }

        pub fn deleteContext(self: *Self, key: K, ctx: Context) ?KV {
            const hash = ctx.hash(key);

            var i = hash >> self.shift;
            while (true) : (i += 1) {
                const entry = self.entries[i] orelse return null;
                if (ctx.hash(entry.key) > hash) return null;
                if (ctx.eql(entry.key, key)) break;
                self.del_probe_count += 1;
            }

            const entry = self.entries[i].?;

            const kv: KV = .{
                .key = entry.key,
                .value = entry.value,
            };

            assert(self.live.remove(entry));
            self.free.prepend(entry);

            self.shiftBackwardsContext(i, ctx);
            self.len -= 1;

            return kv;
        }

        fn shiftBackwards(self: *Self, i_const: usize) void {
            if (@sizeOf(Context) != 0) {
                @compileError("shiftBackwardsContext must be used.");
            }
            self.shiftBackwardsContext(i_const, undefined);
        }

        fn shiftBackwardsContext(self: *Self, i_const: usize, ctx: Context) void {
            var i = i_const;
            while (true) : (i += 1) {
                const next_entry = self.entries[i + 1] orelse break;
                const j = ctx.hash(next_entry.key) >> self.shift;
                if (i < j) break;

                self.entries[i] = self.entries[i + 1];
                self.del_probe_count += 1;
            }

            self.entries[i] = null;
        }
    };
}

pub fn AutoIntrusiveHashMap(
    comptime K: type,
    comptime V: type,
    comptime max_load_percentage: comptime_int,
) type {
    return IntrusiveHashMap(K, V, max_load_percentage, std.hash_map.AutoContext(K));
}

pub fn IntrusiveHashMap(
    comptime K: type,
    comptime V: type,
    comptime max_load_percentage: comptime_int,
    comptime Context: type,
) type {
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
            // The evicted key-value pair.
            evicted: KV,
            /// The last value that was paired with provided key.
            updated: V,
            inserted,
        };

        pub fn update(self: *Self, key: K, value: V) UpdateResult {
            if (@sizeOf(Context) != 0) {
                @compileError("updateContext must be used.");
            }
            return self.updateContext(key, value, undefined);
        }

        /// After calling this method, all pointers to entries except the one returned
        /// should be assumed to have been invalidated.
        pub fn updateContext(self: *Self, key: K, value: V, ctx: Context) UpdateResult {
            const result = self.getOrPutContext(key, ctx);
            const result_value = result.entry.value;

            result.entry.value = value;
            self.moveToFront(result.entry);

            if (result.found_existing) {
                return .{ .updated = result_value };
            }

            const capacity = @as(u64, 1) << (63 - self.shift + 1);
            if (self.len > capacity * max_load_percentage / 100) {
                return .{ .evicted = self.popContext(ctx).? };
            }

            return .inserted;
        }

        pub const GetOrPutResult = struct {
            entry: *Entry,
            found_existing: bool,
        };

        /// Get or put a value at a provided key. If the key exists, the key is moved
        /// to the head of the LRU cache. If the key does not exist, a new entry is
        /// created for the provided value to be placed within. After calling this
        /// method, all pointers to entries except the one returned should be assumed
        /// to have been invalidated.
        pub fn getOrPut(self: *Self, key: K) GetOrPutResult {
            if (@sizeOf(Context) != 0) {
                @compileError("getOrPutContext must be used.");
            }
            return self.getOrPutContext(key, undefined);
        }

        /// Get or put a value at a provided key. If the key exists, the key is moved
        /// to the head of the LRU cache. If the key does not exist, a new entry is
        /// created for the provided value to be placed within. After calling this
        /// method, all pointers to entries except the one returned should be assumed
        /// to have been invalidated.
        pub fn getOrPutContext(self: *Self, key: K, ctx: Context) GetOrPutResult {
            var it: Entry = .{ .key = key, .value = undefined };
            var i = ctx.hash(key) >> self.shift;

            var inserted_at: ?usize = null;
            while (true) : (i += 1) {
                if (self.entries[i].isEmpty(self)) {
                    if (inserted_at != null) {
                        self.readjustNodePointers(&it, &self.entries[i]);
                    }
                    self.entries[i] = it;
                    self.len += 1;
                    return .{
                        .entry = &self.entries[inserted_at orelse i],
                        .found_existing = false,
                    };
                } else if (ctx.hash(self.entries[i].key) > ctx.hash(it.key)) {
                    if (inserted_at == null) {
                        inserted_at = i;
                    } else {
                        self.readjustNodePointers(&it, &self.entries[i]);
                    }
                    mem.swap(Entry, &it, &self.entries[i]);
                } else if (ctx.eql(self.entries[i].key, key)) {
                    assert(inserted_at == null);
                    return .{
                        .entry = &self.entries[i],
                        .found_existing = true,
                    };
                }
                self.put_probe_count += 1;
            }
        }

        pub fn get(self: *Self, key: K) ?*Entry {
            if (@sizeOf(Context) != 0) {
                @compileError("getContext must be used.");
            }
            return self.getContext(key, undefined);
        }

        pub fn getContext(self: *Self, key: K, ctx: Context) ?*Entry {
            const hash = ctx.hash(key);

            var i = hash >> self.shift;
            while (true) : (i += 1) {
                const entry = &self.entries[i];
                if (entry.isEmpty(self) or ctx.hash(entry.key) > hash) {
                    return null;
                } else if (ctx.eql(entry.key, key)) {
                    return entry;
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

        /// Moves the entry to the front of the LRU cache. This method should NOT
        /// be called if getOrPut() or update() or any other methods have been
        /// called that may invalidate pointers to entries in this cache.
        pub fn moveToFront(self: *Self, entry: *Entry) void {
            self.removeNode(entry);
            self.prependNode(entry);
        }

        /// Moves the entry to the end of the LRU cache. This method should NOT
        /// be called if getOrPut() or update() or any other methods have been
        /// called that may invalidate pointers to entries in this cache.
        pub fn moveToBack(self: *Self, entry: *Entry) void {
            self.removeNode(entry);
            self.appendNode(entry);
        }

        pub fn popFirst(self: *Self) ?KV {
            if (@sizeOf(Context) != 0) {
                @compileError("popFirstContext must be used.");
            }
            return self.popFirstContext(undefined);
        }

        pub fn popFirstContext(self: *Self, ctx: Context) ?KV {
            const head = self.head orelse return null;
            const head_index = (@ptrToInt(head) - @ptrToInt(self.entries)) / @sizeOf(Entry);
            return KV{ .key = head.key, .value = self.deleteEntryAtIndex(head_index, ctx) };
        }

        pub fn pop(self: *Self) ?KV {
            if (@sizeOf(Context) != 0) {
                @compileError("popContext must be used.");
            }
            return self.popContext(undefined);
        }

        pub fn popContext(self: *Self, ctx: Context) ?KV {
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

        /// Prepend entry to head of linked list.
        fn prependNode(self: *Self, entry: *Entry) void {
            assert(entry.prev == null);
            assert(entry.next == null);
            if (self.head) |head| {
                head.prev = entry;
            } else {
                self.tail = entry;
            }
            entry.next = self.head;
            self.head = entry;
        }

        /// Append entry to tail of linked list.
        fn appendNode(self: *Self, entry: *Entry) void {
            assert(entry.prev == null);
            assert(entry.next == null);
            if (self.tail) |tail| {
                tail.next = entry;
            } else {
                self.head = entry;
            }
            entry.prev = self.tail;
            self.tail = entry;
        }

        /// Remove entry from the linked list.
        fn removeNode(self: *Self, entry: *Entry) void {
            if (self.head == null) {
                return;
            }
            if (self.head != entry and entry.next == null and entry.prev == null) {
                return;
            }
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
        const result = map.getOrPut(i);
        try testing.expect(!result.found_existing);
        result.node.value = i;
        map.moveToFront(result.node);
    }

    while (i < 8) : (i += 1) {
        const result = map.getOrPut(i);

        try testing.expect(!result.found_existing);
        result.node.value = i;
        map.moveToFront(result.node);

        const evicted = result.evicted orelse return error.EvictionExpected;
        try testing.expectEqual(i - 4, evicted.key);
        try testing.expectEqual(i - 4, evicted.value);
    }

    try testing.expectEqual(@as(usize, 4), map.len);

    try testing.expectEqual(@as(usize, 7), map.live.head.?.key);
    try testing.expectEqual(@as(usize, 7), map.live.head.?.value);

    try testing.expectEqual(@as(usize, 4), map.live.tail.?.key);
    try testing.expectEqual(@as(usize, 4), map.live.tail.?.value);

    var it = map.live.head;
    while (it) |node| : (it = node.next) {
        try testing.expectEqual(i - 1, node.key);
        try testing.expectEqual(i - 1, node.value);
        i -= 1;
    }

    while (i < 8) : (i += 1) {
        const kv = map.delete(i) orelse return error.ExpectedSuccessfulDeletion;
        try testing.expectEqual(i, kv.key);
        try testing.expectEqual(i, kv.value);
    }
    try testing.expectEqual(@as(usize, 0), map.len);
    try testing.expectEqual(@as(?*Cache.Entry, null), map.live.head);
    try testing.expectEqual(@as(?*Cache.Entry, null), map.live.tail);
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

        for (keys) |key, i| {
            const result = map.getOrPut(key);
            try testing.expect(!result.found_existing);
            try testing.expect(result.evicted == null);
            result.node.value = i;
            map.moveToFront(result.node);
        }

        for (keys) |key, i| try testing.expectEqual(i, map.get(key).?.value);
        try testing.expectEqual(keys.len, map.len);

        try testing.expectEqual(keys[keys.len - 1], map.live.head.?.key);
        try testing.expectEqual(keys.len - 1, map.live.head.?.value);

        try testing.expectEqual(keys[0], map.live.tail.?.key);
        try testing.expectEqual(@as(usize, 0), map.live.tail.?.value);

        // randomly promote half of all entries to head except tail

        var key_index: usize = 0;
        while (key_index < keys.len / 2) : (key_index += 1) {
            const index = rng.random.intRangeAtMost(usize, 1, keys.len - 1);

            const result = map.getOrPut(keys[index]);
            try testing.expect(result.found_existing);
            try testing.expect(result.evicted == null);
            result.node.value = index;
            map.moveToFront(result.node);

            try testing.expectEqual(keys[index], map.live.head.?.key);
            try testing.expectEqual(index, map.live.head.?.value);

            try testing.expectEqual(keys[0], map.live.tail.?.key);
            try testing.expectEqual(@as(usize, 0), map.live.tail.?.value);
        }

        // promote tail to head

        const expected = map.live.tail.?.prev.?;

        const result = map.getOrPut(keys[0]);
        try testing.expect(result.found_existing);
        try testing.expect(result.evicted == null);
        result.node.value = 0;
        map.moveToFront(result.node);

        for (keys) |key, i| try testing.expectEqual(i, map.get(key).?.value);
        try testing.expectEqual(keys.len, map.len);

        try testing.expectEqual(keys[0], map.live.head.?.key);
        try testing.expectEqual(@as(usize, 0), map.live.head.?.value);

        try testing.expectEqual(expected.key, map.live.tail.?.key);
        try testing.expectEqual(expected.value, map.live.tail.?.value);

        // delete all entries

        for (keys) |key, i| try testing.expectEqual(i, map.delete(key).?.value);
        try testing.expectEqual(@as(usize, 0), map.len);
        try testing.expectEqual(@as(?*Cache.Entry, null), map.live.head);
        try testing.expectEqual(@as(?*Cache.Entry, null), map.live.tail);
    }
}

test "lru.IntrusiveHashMap: eviction on insert" {
    const Cache = AutoIntrusiveHashMap(usize, usize, 100);

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

test "lru.IntrusiveHashMap: update, get, delete without eviction" {
    const Cache = AutoIntrusiveHashMap(usize, usize, 100);

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
        for (keys) |key, i| try testing.expectEqual(i, map.get(key).?.value);
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
        for (keys) |key, i| try testing.expectEqual(i, map.get(key).?.value);
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
