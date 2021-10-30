const std = @import("std");

const mem = std.mem;
const math = std.math;
const rand = std.rand;
const meta = std.meta;
const testing = std.testing;

pub fn SkipList(comptime T: type) type {
    const Key = []const u8;

    return struct {
        pub const num_levels = 25;

        pub const Element = struct {
            next: [num_levels]?*Element = [_]?*Element{null} ** num_levels,
            prev: ?*Element = null,
            level: usize,
            value: T,

            pub fn getKey(self: *Element) Key {
                if (comptime meta.trait.isIndexable(T)) {
                    return &self.value;
                }
                return self.value.getKey();
            }
        };

        const Self = @This();

        start_levels: [num_levels]?*Element = [_]?*Element{null} ** num_levels,
        end_levels: [num_levels]?*Element = [_]?*Element{null} ** num_levels,

        max_new_level: usize = num_levels,
        max_level: usize = 0,
        element_count: usize = 0,

        rng: std.rand.DefaultPrng = std.rand.DefaultPrng.init(0),

        pub fn deinit(self: *Self, gpa: *mem.Allocator) void {
            var it = self.start_levels[0];
            while (it) |node| {
                it = node.next[0];
                gpa.destroy(node);
            }
        }

        pub fn isEmpty(self: *Self) bool {
            return self.start_levels[0] == null;
        }

        pub fn generateLevel(self: *Self, max_level: usize) usize {
            const x = self.rng.random().int(u64) & ((@as(u64, 1) << @intCast(u6, max_level)) - 1);
            const zeroes = @ctz(u64, x);
            if (zeroes <= max_level) {
                return zeroes;
            }
            return max_level - 1;
        }

        pub fn findEntryIndex(self: *Self, key: Key, level: usize) usize {
            var i: usize = self.max_level + 1;
            while (i > 0) : (i -= 1) {
                const element = self.start_levels[i - 1] orelse continue;
                if (mem.order(u8, element.getKey(), key).compare(.lte) or (i - 1) <= level) {
                    return i - 1;
                }
            }
            return 0;
        }

        pub fn find(self: *Self, key: Key) ?*Element {
            var index = self.findEntryIndex(key, 0);
            var current_node = self.start_levels[index] orelse return null;

            while (true) {
                if (mem.order(u8, current_node.getKey(), key) == .eq) {
                    return current_node;
                }

                if (current_node.next[index]) |next_node| {
                    if (mem.order(u8, next_node.getKey(), key).compare(.lte)) {
                        current_node = next_node;
                        continue;
                    }
                }

                if (index == 0) {
                    return null;
                }

                if (current_node.next[0]) |next_node| {
                    if (mem.order(u8, next_node.getKey(), key) == .eq) {
                        return next_node;
                    }
                    index -= 1;
                }
            }
        }

        pub fn insert(self: *Self, gpa: *mem.Allocator, value: T) !void {
            const element = try gpa.create(Element);
            errdefer gpa.destroy(element);

            var level = self.generateLevel(self.max_new_level);
            if (level > self.max_level) {
                level = self.max_level + 1;
                self.max_level = level;
            }

            element.* = .{ .level = level, .value = value };
            self.element_count += 1;

            var new_first = true;
            var new_last = true;
            if (!self.isEmpty()) {
                new_first = mem.order(u8, element.getKey(), self.start_levels[0].?.getKey()) == .lt;
                new_last = mem.order(u8, element.getKey(), self.end_levels[0].?.getKey()) == .gt;
            }

            var normally_inserted = false;
            if (!new_first and !new_last) {
                normally_inserted = true;

                var index = self.findEntryIndex(element.getKey(), level);
                var current_node_ptr: ?*Element = null;
                var next_node_ptr: ?*Element = self.start_levels[index];

                while (true) {
                    if (current_node_ptr) |current_node| {
                        next_node_ptr = current_node.next[index];
                    } else {
                        next_node_ptr = self.start_levels[index];
                    }

                    if (index <= level) {
                        if (next_node_ptr) |next_node| {
                            if (mem.order(u8, next_node.getKey(), element.getKey()) == .gt) {
                                element.next[index] = next_node_ptr;
                                if (current_node_ptr) |current_node| {
                                    current_node.next[index] = element;
                                }
                                if (index == 0) {
                                    element.prev = current_node_ptr;
                                    next_node.prev = element;
                                }
                            }
                        } else {
                            element.next[index] = next_node_ptr;
                            if (current_node_ptr) |current_node| {
                                current_node.next[index] = element;
                            }
                            if (index == 0) {
                                element.prev = current_node_ptr;
                            }
                        }
                    }

                    if (next_node_ptr) |next_node| {
                        if (mem.order(u8, next_node.getKey(), element.getKey()).compare(.lte)) {
                            current_node_ptr = next_node;
                            continue;
                        }
                    }

                    if (index == 0) break;

                    index -= 1;
                }
            }

            var i: usize = level + 1;
            while (i > 0) : (i -= 1) {
                var did_something = false;
                if (new_first or normally_inserted) {
                    if (self.start_levels[i - 1]) |start_node| {
                        if (mem.order(u8, start_node.getKey(), element.getKey()) == .gt) {
                            if (i - 1 == 0) {
                                start_node.prev = element;
                            }
                            element.next[i - 1] = start_node;
                            self.start_levels[i - 1] = element;
                        }
                    } else {
                        element.next[i - 1] = null;
                        self.start_levels[i - 1] = element;
                    }

                    if (element.next[i - 1] == null) {
                        self.end_levels[i - 1] = element;
                    }

                    did_something = true;
                }

                if (new_last) {
                    if (!new_first) {
                        if (self.end_levels[i - 1]) |end_node| {
                            end_node.next[i - 1] = element;
                        }
                        if (i - 1 == 0) {
                            element.prev = self.end_levels[i - 1];
                        }
                        self.end_levels[i - 1] = element;
                    }

                    if (self.start_levels[i - 1]) |start_node| {
                        if (mem.order(u8, start_node.getKey(), element.getKey()) == .gt) {
                            self.start_levels[i - 1] = element;
                        }
                    } else {
                        self.start_levels[i - 1] = element;
                    }

                    did_something = true;
                }

                if (!did_something) {
                    break;
                }
            }
        }
    };
}

test {
    const Hash = struct {
        key: []const u8,

        pub fn getKey(self: @This()) []const u8 {
            return self.key;
        }
    };
    testing.refAllDecls(SkipList(Hash));
}

test "insert" {
    const Hash = struct {
        key: []const u8,

        pub fn getKey(self: @This()) []const u8 {
            return self.key;
        }
    };

    var list: SkipList(Hash) = .{};
    defer list.deinit(testing.allocator);

    try list.insert(testing.allocator, Hash{ .key = "hello" });
    try testing.expect(list.find("hello") != null);
    try testing.expect(list.find("hello world") == null);
    try list.insert(testing.allocator, Hash{ .key = "hello world" });
    try testing.expect(list.find("hello") != null);
    try testing.expect(list.find("hello world") != null);
}

test "stress insert" {
    var rng = std.rand.DefaultPrng.init(0);

    var inputs = try testing.allocator.alloc([32]u8, 10_000);
    defer testing.allocator.free(inputs);

    var list: SkipList([32]u8) = .{};
    defer list.deinit(testing.allocator);

    for (inputs) |*input| rng.random().bytes(input);
    for (inputs) |input| try list.insert(testing.allocator, input);
}
