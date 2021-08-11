const std = @import("std");

const mem = std.mem;
const math = std.math;
const testing = std.testing;

const assert = std.debug.assert;

/// The following routine has its branches optimized against inputs that are cryptographic hashes by
/// assuming that if the first 64 bits of 'a' and 'b' are equivalent, then 'a' and 'b' are most likely
/// equivalent.
fn cmp(a: [32]u8, b: [32]u8) math.Order {
    const msa = @bitCast(u64, a[0..8].*);
    const msb = @bitCast(u64, b[0..8].*);
    if (msa != msb) {
        return if (mem.bigToNative(u64, msa) < mem.bigToNative(u64, msb)) .lt else .gt;
    } else if (@reduce(.And, @as(std.meta.Vector(32, u8), a) == @as(std.meta.Vector(32, u8), b))) {
        return .eq;
    } else {
        switch (math.order(mem.readIntBig(u64, a[8..16]), mem.readIntBig(u64, b[8..16]))) {
            .eq => {},
            .lt => return .lt,
            .gt => return .gt,
        }
        switch (math.order(mem.readIntBig(u64, a[16..24]), mem.readIntBig(u64, b[16..24]))) {
            .eq => {},
            .lt => return .lt,
            .gt => return .gt,
        }
        return math.order(mem.readIntBig(u64, a[24..32]), mem.readIntBig(u64, b[24..32]));
    }
}

/// In release-fast mode, LLVM will optimize this routine to utilize 109 cycles. This routine scatters
/// hash values across a table into buckets which are lexicographically ordered from one another in
/// ascending order. 
fn idx(a: [32]u8, shift: u6) usize {
    return @intCast(usize, mem.readIntBig(u64, a[0..8]) >> shift);
}

pub fn HashMap(comptime V: type, comptime max_load_percentage: comptime_int) type {
    return struct {
        const empty_hash: [32]u8 = [_]u8{0xFF} ** 32;

        pub const Entry = struct {
            hash: [32]u8 = empty_hash,
            value: V = undefined,

            pub fn isEmpty(self: Entry) bool {
                return cmp(self.hash, empty_hash) == .eq;
            }

            pub fn format(self: Entry, comptime layout: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
                _ = layout;
                _ = options;
                try std.fmt.format(writer, "(hash: {}, value: {})", .{ std.fmt.fmtSliceHexLower(mem.asBytes(&self.hash)), self.value });
            }
        };

        const Self = @This();

        entries: [*]Entry,
        len: usize = 0,
        shift: u6,

        put_probe_count: usize = 0,
        get_probe_count: usize = 0,
        del_probe_count: usize = 0,

        pub fn init(gpa: *mem.Allocator) !Self {
            return Self.initCapacity(gpa, 16);
        }

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

        pub fn clearRetainingCapacity(self: *Self) void {
            mem.set(Entry, self.slice(), .{});
            self.len = 0;
        }

        pub fn slice(self: *Self) []Entry {
            const capacity = @as(u64, 1) << (63 - self.shift + 1);
            const overflow = capacity / 10 + (63 - @as(usize, self.shift) + 1) << 1;
            return self.entries[0..@intCast(usize, capacity + overflow)];
        }

        pub fn ensureUnusedCapacity(self: *Self, gpa: *mem.Allocator, count: usize) !void {
            try self.ensureTotalCapacity(gpa, self.len + count);
        }

        pub fn ensureTotalCapacity(self: *Self, gpa: *mem.Allocator, count: usize) !void {
            while (true) {
                const capacity = @as(u64, 1) << (63 - self.shift + 1);
                if (count <= capacity * max_load_percentage / 100) {
                    break;
                }
                try self.grow(gpa);
            }
        }

        pub fn grow(self: *Self, gpa: *mem.Allocator) !void {
            const capacity = @as(u64, 1) << (63 - self.shift + 1);
            const overflow = capacity / 10 + (63 - @as(usize, self.shift) + 1) << 1;
            const end = self.entries + @intCast(usize, capacity + overflow);

            var map = try Self.initCapacity(gpa, @intCast(usize, capacity * 2));
            var src = self.entries;
            var dst = map.entries;

            while (src != end) {
                const entry = src[0];

                const i = if (!entry.isEmpty()) idx(entry.hash, map.shift) else 0;
                const p = map.entries + i;

                dst = if (@ptrToInt(p) >= @ptrToInt(dst)) p else dst;
                dst[0] = entry;

                src += 1;
                dst += 1;
            }

            self.deinit(gpa);
            self.entries = map.entries;
            self.shift = map.shift;
        }

        pub fn put(self: *Self, gpa: *mem.Allocator, key: [32]u8, value: V) !void {
            try self.ensureUnusedCapacity(gpa, 1);
            self.putAssumeCapacity(key, value);
        }

        pub fn putAssumeCapacity(self: *Self, key: [32]u8, value: V) void {
            assert(cmp(key, empty_hash) != .eq);

            var it: Entry = .{ .hash = key, .value = value };
            var i = idx(key, self.shift);
            while (true) : (i += 1) {
                const entry = self.entries[i];
                if (cmp(entry.hash, it.hash).compare(.gte)) {
                    self.entries[i] = it;
                    if (cmp(entry.hash, key) == .eq) {
                        return;
                    }
                    if (entry.isEmpty()) {
                        self.len += 1;
                        return;
                    }
                    it = entry;
                }
                self.put_probe_count += 1;
            }
        }

        pub fn get(self: *Self, key: [32]u8) ?V {
            assert(cmp(key, empty_hash) != .eq);

            var i = idx(key, self.shift);
            while (true) : (i += 1) {
                const entry = self.entries[i];
                if (cmp(entry.hash, key).compare(.gte)) {
                    if (cmp(entry.hash, key) != .eq) {
                        return null;
                    }
                    return entry.value;
                }
                self.get_probe_count += 1;
            }
        }

        pub fn delete(self: *Self, key: [32]u8) ?V {
            assert(cmp(key, empty_hash) != .eq);

            var i = idx(key, self.shift);
            while (true) : (i += 1) {
                const entry = self.entries[i];
                if (cmp(entry.hash, key).compare(.gte)) {
                    if (cmp(entry.hash, key) != .eq) {
                        return null;
                    }
                    break;
                }
                self.del_probe_count += 1;
            }

            const value = self.entries[i].value;

            while (true) : (i += 1) {
                const j = idx(self.entries[i + 1].hash, self.shift);
                if (i < j or self.entries[i + 1].isEmpty()) {
                    break;
                }
                self.entries[i] = self.entries[i + 1];
                self.del_probe_count += 1;
            }
            self.entries[i] = .{};
            self.len -= 1;

            return value;
        }
    };
}

test "hash map: cmp" {
    const prefix = [_]u8{'0'} ** 8 ++ [_]u8{'1'} ** 23;
    const a = prefix ++ [_]u8{0};
    const b = prefix ++ [_]u8{1};

    try testing.expect(cmp(a, b) == .lt);
    try testing.expect(cmp(b, a) == .gt);
    try testing.expect(cmp(a, a) == .eq);
    try testing.expect(cmp(b, b) == .eq);
    try testing.expect(cmp([_]u8{'i'} ++ [_]u8{'0'} ** 31, [_]u8{'o'} ++ [_]u8{'0'} ** 31) == .lt);
    try testing.expect(cmp([_]u8{ 'h', 'i' } ++ [_]u8{'0'} ** 30, [_]u8{ 'h', 'o' } ++ [_]u8{'0'} ** 30) == .lt);
}

test "hash map: put, get, delete, grow" {
    var seed: usize = 0;
    while (seed < 128) : (seed += 1) {
        var rng = std.rand.DefaultPrng.init(seed);

        const keys = try testing.allocator.alloc([32]u8, 512);
        defer testing.allocator.free(keys);

        for (keys) |*key| rng.random.bytes(key);

        var map = try HashMap(usize, 50).initCapacity(testing.allocator, 16);
        defer map.deinit(testing.allocator);

        try testing.expectEqual(@as(u6, 60), map.shift);

        for (keys) |key, i| try map.put(testing.allocator, key, i);

        try testing.expectEqual(@as(u6, 54), map.shift);
        try testing.expectEqual(keys.len, map.len);

        var it = [_]u8{0} ** 32;
        for (map.slice()) |entry| {
            if (!entry.isEmpty()) {
                if (!mem.order(u8, &it, &entry.hash).compare(.lte)) {
                    return error.Unsorted;
                }
                it = entry.hash;
            }
        }

        for (keys) |key, i| try testing.expectEqual(i, map.get(key).?);
        for (keys) |key, i| try testing.expectEqual(i, map.delete(key).?);
    }
}

test "hash map: collision test" {
    const prefix = [_]u8{22} ** 8 ++ [_]u8{1} ** 23;

    var map = try HashMap(usize, 100).initCapacity(testing.allocator, 4);
    defer map.deinit(testing.allocator);

    try map.put(testing.allocator, prefix ++ [_]u8{0}, 0);
    try map.put(testing.allocator, prefix ++ [_]u8{1}, 1);
    try map.put(testing.allocator, prefix ++ [_]u8{2}, 2);
    try map.put(testing.allocator, prefix ++ [_]u8{3}, 3);

    var it = [_]u8{0} ** 32;
    for (map.slice()) |entry| {
        if (!entry.isEmpty()) {
            if (!mem.order(u8, &it, &entry.hash).compare(.lte)) {
                return error.Unsorted;
            }
            it = entry.hash;
        }
    }

    try testing.expectEqual(@as(usize, 0), map.get(prefix ++ [_]u8{0}).?);
    try testing.expectEqual(@as(usize, 1), map.get(prefix ++ [_]u8{1}).?);
    try testing.expectEqual(@as(usize, 2), map.get(prefix ++ [_]u8{2}).?);
    try testing.expectEqual(@as(usize, 3), map.get(prefix ++ [_]u8{3}).?);

    try testing.expectEqual(@as(usize, 2), map.delete(prefix ++ [_]u8{2}).?);
    try testing.expectEqual(@as(usize, 0), map.delete(prefix ++ [_]u8{0}).?);
    try testing.expectEqual(@as(usize, 1), map.delete(prefix ++ [_]u8{1}).?);
    try testing.expectEqual(@as(usize, 3), map.delete(prefix ++ [_]u8{3}).?);

    try map.put(testing.allocator, prefix ++ [_]u8{0}, 0);
    try map.put(testing.allocator, prefix ++ [_]u8{2}, 2);
    try map.put(testing.allocator, prefix ++ [_]u8{3}, 3);
    try map.put(testing.allocator, prefix ++ [_]u8{1}, 1);

    it = [_]u8{0} ** 32;
    for (map.slice()) |entry| {
        if (!entry.isEmpty()) {
            if (!mem.order(u8, &it, &entry.hash).compare(.lte)) {
                return error.Unsorted;
            }
            it = entry.hash;
        }
    }

    try testing.expectEqual(@as(usize, 0), map.delete(prefix ++ [_]u8{0}).?);
    try testing.expectEqual(@as(usize, 1), map.delete(prefix ++ [_]u8{1}).?);
    try testing.expectEqual(@as(usize, 2), map.delete(prefix ++ [_]u8{2}).?);
    try testing.expectEqual(@as(usize, 3), map.delete(prefix ++ [_]u8{3}).?);

    try map.put(testing.allocator, prefix ++ [_]u8{0}, 0);
    try map.put(testing.allocator, prefix ++ [_]u8{2}, 2);
    try map.put(testing.allocator, prefix ++ [_]u8{1}, 1);
    try map.put(testing.allocator, prefix ++ [_]u8{3}, 3);

    it = [_]u8{0} ** 32;
    for (map.slice()) |entry| {
        if (!entry.isEmpty()) {
            if (!mem.order(u8, &it, &entry.hash).compare(.lte)) {
                return error.Unsorted;
            }
            it = entry.hash;
        }
    }

    try testing.expectEqual(@as(usize, 3), map.delete(prefix ++ [_]u8{3}).?);
    try testing.expectEqual(@as(usize, 2), map.delete(prefix ++ [_]u8{2}).?);
    try testing.expectEqual(@as(usize, 1), map.delete(prefix ++ [_]u8{1}).?);
    try testing.expectEqual(@as(usize, 0), map.delete(prefix ++ [_]u8{0}).?);

    try map.put(testing.allocator, prefix ++ [_]u8{3}, 3);
    try map.put(testing.allocator, prefix ++ [_]u8{0}, 0);
    try map.put(testing.allocator, prefix ++ [_]u8{1}, 1);
    try map.put(testing.allocator, prefix ++ [_]u8{2}, 2);

    it = [_]u8{0} ** 32;
    for (map.slice()) |entry| {
        if (!entry.isEmpty()) {
            if (!mem.order(u8, &it, &entry.hash).compare(.lte)) {
                return error.Unsorted;
            }
            it = entry.hash;
        }
    }

    try testing.expectEqual(@as(usize, 3), map.delete(prefix ++ [_]u8{3}).?);
    try testing.expectEqual(@as(usize, 0), map.delete(prefix ++ [_]u8{0}).?);
    try testing.expectEqual(@as(usize, 1), map.delete(prefix ++ [_]u8{1}).?);
    try testing.expectEqual(@as(usize, 2), map.delete(prefix ++ [_]u8{2}).?);
}
