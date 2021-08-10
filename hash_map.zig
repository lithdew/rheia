const std = @import("std");

const mem = std.mem;
const math = std.math;
const testing = std.testing;

const assert = std.debug.assert;

pub fn HashMap(comptime V: type, comptime max_load_percentage: comptime_int) type {
    return struct {
        const empty_hash: u256 = math.maxInt(u256);

        pub const Entry = struct {
            hash: u256 = empty_hash,
            value: V = undefined,

            pub fn isEmpty(self: Entry) bool {
                return self.hash == empty_hash;
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

        pub fn initCapacity(gpa: *mem.Allocator, capacity: usize) !Self {
            assert(math.isPowerOfTwo(capacity));

            const shift = 63 - math.log2_int(u64, capacity) + 1;
            const overflow = capacity / 10 + (63 - @as(usize, shift) + 1) << 1;

            const entries = try gpa.alloc(Entry, capacity + overflow);
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
            return self.entries[0 .. capacity + overflow];
        }

        pub fn ensureUnusedCapacity(self: *Self, gpa: *mem.Allocator, count: usize) !void {
            try self.ensureTotalCapacity(gpa, self.len + count);
        }

        pub fn ensureTotalCapacity(self: *Self, gpa: *mem.Allocator, count: usize) !void {
            while (true) {
                const capacity = @as(u64, 1) << (63 - self.shift + 1);
                if (count < capacity * max_load_percentage / 100) {
                    break;
                }
                try self.grow(gpa);
            }
        }

        pub fn grow(self: *Self, gpa: *mem.Allocator) !void {
            const capacity = @as(u64, 1) << (63 - self.shift + 1);
            const overflow = capacity / 10 + (63 - @as(usize, self.shift) + 1) << 1;
            const end = self.entries + capacity + overflow;

            var map = try Self.initCapacity(gpa, capacity * 2);
            var src = self.entries;
            var dst = map.entries;

            while (src != end) {
                const entry = src[0];

                const i = if (entry.hash != empty_hash) @byteSwap(u64, @bitCast(u64, @ptrCast(*const [32]u8, &entry.hash)[0..8].*)) >> map.shift else 0;
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
            const hash = @bitCast(u256, key);
            assert(hash != empty_hash);

            var it: Entry = .{ .hash = hash, .value = value };
            var i = @byteSwap(u64, @bitCast(u64, key[0..8].*)) >> self.shift;
            while (true) : (i += 1) {
                const entry = self.entries[i];

                if (@byteSwap(u64, @bitCast(u64, @ptrCast(*const [32]u8, &it.hash)[0..8].*)) <= @byteSwap(u64, @bitCast(u64, @ptrCast(*const [32]u8, &entry.hash)[0..8].*))) {
                    self.entries[i] = it;
                    if (entry.hash == hash) {
                        return;
                    }
                    if (entry.hash == empty_hash) {
                        self.len += 1;
                        return;
                    }
                    it = entry;
                }
                self.put_probe_count += 1;
            }
        }

        pub fn get(self: *Self, key: [32]u8) ?V {
            const hash = @bitCast(u256, key);
            assert(hash != empty_hash);

            var i = @byteSwap(u64, @bitCast(u64, key[0..8].*)) >> self.shift;
            while (true) : (i += 1) {
                const entry = self.entries[i];
                if (@byteSwap(u64, @bitCast(u64, key[0..8].*)) <= @byteSwap(u64, @bitCast(u64, @ptrCast(*const [32]u8, &entry.hash)[0..8].*))) {
                    if (entry.hash != hash) {
                        return null;
                    }
                    return entry.value;
                }

                self.get_probe_count += 1;
            }
        }

        pub fn delete(self: *Self, key: [32]u8) ?V {
            const hash = @bitCast(u256, key);
            assert(hash != empty_hash);

            var i = @byteSwap(u64, @bitCast(u64, key[0..8].*)) >> self.shift;
            while (true) : (i += 1) {
                const entry = self.entries[i];
                if (@byteSwap(u64, @bitCast(u64, key[0..8].*)) <= @byteSwap(u64, @bitCast(u64, @ptrCast(*const [32]u8, &entry.hash)[0..8].*))) {
                    if (entry.hash != hash) {
                        return null;
                    }
                    break;
                }
                self.del_probe_count += 1;
            }

            const value = self.entries[i].value;

            while (true) : (i += 1) {
                const j = @byteSwap(u64, @bitCast(u64, @ptrCast(*const [32]u8, &self.entries[i + 1].hash)[0..8].*)) >> self.shift;
                if (i < j or self.entries[i + 1].hash == empty_hash) {
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

test "hash map: put, get, delete, grow" {
    var rng = std.rand.DefaultPrng.init(1);

    const keys = try testing.allocator.alloc([32]u8, 512);
    defer testing.allocator.free(keys);

    for (keys) |*key| rng.random.bytes(key);

    var map = try HashMap(usize, 50).initCapacity(testing.allocator, 16);
    defer map.deinit(testing.allocator);

    try testing.expectEqual(@as(u6, 60), map.shift);

    for (keys) |key, i| try map.put(testing.allocator, key, i);

    try testing.expectEqual(@as(u6, 54), map.shift);
    try testing.expectEqual(keys.len, map.len);

    for (keys) |key, i| try testing.expectEqual(i, map.get(key).?);
    for (keys) |key, i| try testing.expectEqual(i, map.delete(key).?);

    try testing.expectEqual(@as(usize, 0), map.len);
    try testing.expectEqual(@as(usize, 406), map.put_probe_count);
    try testing.expectEqual(@as(usize, 251), map.get_probe_count);
    try testing.expectEqual(@as(usize, 251), map.del_probe_count);
}
