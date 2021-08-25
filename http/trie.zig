const std = @import("std");

const mem = std.mem;
const math = std.math;
const testing = std.testing;

const panic = std.debug.panic;

pub fn Node(comptime V: type) type {
    return struct {
        const Self = @This();

        const Label = enum(u8) {
            static,
            root,
            param,
            catch_all,
        };

        path: []const u8 = &[_]u8{},
        indices: []const u8 = &[_]u8{},
        wild_child: bool = false,
        label: Self.Label = .static,
        priority: u32 = 0,
        children: []*Self = &[_]*Self{},
        value: ?V = null,

        fn incrementChildPriority(comptime self: *Self, pos: usize) usize {
            self.children[pos].priority += 1;
            const priority = self.children[pos].priority;

            var new_pos = pos;
            while (new_pos > 0 and self.children[new_pos - 1].priority < priority) : (new_pos -= 1) {
                mem.swap(*Self, &self.children[new_pos - 1], &self.children[new_pos]);
            }

            if (new_pos != pos) {
                var indices: [self.indices.len]u8 = undefined;
                mem.copy(u8, &indices, self.indices[0..new_pos] ++
                    self.indices[pos..][0..1] ++
                    self.indices[new_pos..pos] ++
                    self.indices[pos + 1 ..]);
                self.indices = &indices;
            }

            return new_pos;
        }

        pub const GetResult = union(enum) {
            found: V,
            not_found,
            trailing_slash_redirect,
        };

        pub fn get(self_const: *const Self, path_const: []const u8, params: anytype) GetResult {
            var self = self_const;
            var path = path_const;

            walk: while (true) {
                var prefix = self.path;
                if (path.len > prefix.len) {
                    if (mem.eql(u8, path[0..prefix.len], prefix)) {
                        path = path[prefix.len..];
                        if (!self.wild_child) {
                            const index_character = path[0];
                            for (self.indices) |character, index| {
                                if (character == index_character) {
                                    self = self.children[index];
                                    continue :walk;
                                }
                            }

                            if (mem.eql(u8, path, "/") and self.value != null) {
                                return .trailing_slash_redirect;
                            }
                            return .not_found;
                        }

                        self = self.children[0];
                        switch (self.label) {
                            .param => {
                                var end: usize = 0;
                                while (end < path.len and path[end] != '/') {
                                    end += 1;
                                }

                                params.next(self.path[1..], path[0..end]);

                                if (end < path.len) {
                                    if (self.children.len > 0) {
                                        path = path[end..];
                                        self = self.children[0];
                                        continue :walk;
                                    }

                                    if (path.len == end + 1) {
                                        return .trailing_slash_redirect;
                                    }
                                    return .not_found;
                                }

                                if (self.value) |value| {
                                    return .{ .found = value };
                                }

                                if (self.children.len == 1) {
                                    self = self.children[0];
                                    if (mem.eql(u8, self.path, "/") and self.value != null) {
                                        return .trailing_slash_redirect;
                                    }
                                    if (self.path.len == 0 and mem.eql(u8, self.indices, "/")) {
                                        return .trailing_slash_redirect;
                                    }
                                }

                                return .not_found;
                            },
                            .catch_all => {
                                params.next(self.path[2..], path);

                                return .{ .found = self.value orelse panic("Path '{s}' has an empty value", .{self.path}) };
                            },
                            else => panic("Walked to invalid node type '{s}'", .{@tagName(self.label)}),
                        }
                    }
                } else if (mem.eql(u8, path, prefix)) {
                    if (self.value) |value| {
                        return .{ .found = value };
                    }

                    if (mem.eql(u8, path, "/") and self.wild_child and self.label != .root) {
                        return .trailing_slash_redirect;
                    }

                    for (self.indices) |character, index| {
                        if (character == '/') {
                            self = self.children[index];
                            if (self.path.len == 1 and self.value != null) {
                                return .trailing_slash_redirect;
                            }
                            if (self.label == .catch_all and self.children[0].value != null) {
                                return .trailing_slash_redirect;
                            }
                            return .not_found;
                        }
                    }

                    return .not_found;
                }

                if (mem.eql(u8, path, "/")) {
                    return .trailing_slash_redirect;
                }
                if (prefix.len == path.len + 1 and prefix[path.len] == '/' and mem.eql(u8, path, prefix[0 .. prefix.len - 1]) and self.value != null) {
                    return .trailing_slash_redirect;
                }
                return .not_found;
            }
        }

        pub fn put(comptime self_const: *Self, comptime path_const: []const u8, value: V) void {
            var self = self_const;
            var path = path_const;

            var full_path = path_const;
            self.priority += 1;

            if (self.path.len == 0 and self.indices.len == 0) {
                self.insertChild(path, full_path, value);
                self.label = .root;
                return;
            }

            walk: while (true) {
                var i = longestCommonPrefix(path, self.path);
                if (i < self.path.len) {
                    var child: Self = .{
                        .path = self.path[i..],
                        .wild_child = self.wild_child,
                        .label = .static,
                        .indices = self.indices,
                        .children = self.children,
                        .value = self.value,
                        .priority = self.priority - 1,
                    };
                    var children = [_]*Self{&child};
                    self.children = &children;
                    self.indices = &[_]u8{self.path[i]};
                    self.path = path[0..i];
                    self.value = null;
                    self.wild_child = false;
                }

                if (i < path.len) {
                    path = path[i..];

                    if (self.wild_child) {
                        self = self.children[0];
                        self.priority += 1;

                        if (path.len >= self.path.len and mem.eql(u8, self.path, path[0..self.path.len]) and self.label != .catch_all and (self.path.len >= path.len or path[self.path.len] == '/')) {
                            continue :walk;
                        } else {
                            var path_segment = path;
                            if (self.label != .catch_all) {
                                var it = mem.split(u8, path_segment, "/");
                                path_segment = it.next().?;
                            }
                            const prefix = full_path[0..mem.indexOf(u8, full_path, path_segment).?] ++ self.path;
                            @compileError("'" ++ path_segment ++ "' in new path '" ++ full_path ++ "' conflicts with existing wildcard '" ++ self.path ++ "' in existing prefix '" ++ prefix ++ "'");
                        }
                    }

                    const index_character = path[0];

                    if (self.label == .param and index_character == '/' and self.children.len == 1) {
                        self = self.children[0];
                        self.priority += 1;
                        continue :walk;
                    }

                    for (self.indices) |character, index| {
                        if (character == index_character) {
                            self = self.children[self.incrementChildPriority(index)];
                            continue :walk;
                        }
                    }

                    if (index_character != ':' and index_character != '*') {
                        self.indices = self.indices ++ &[_]u8{index_character};
                        var child: Self = .{};
                        var children: [self.children.len + 1]*Self = undefined;
                        mem.copy(*Self, &children, self.children ++ [_]*Self{&child});
                        self.children = &children;
                        _ = self.incrementChildPriority(self.indices.len - 1);
                        self = &child;
                    }
                    self.insertChild(path, full_path, value);
                    return;
                }

                if (self.value != null) {
                    @compileError("Path '" ++ full_path ++ "' is already registered");
                }
                self.value = value;
                return;
            }
        }

        fn insertChild(comptime self_const: *Self, comptime path_const: []const u8, comptime full_path: []const u8, value: V) void {
            var self = self_const;
            var path = path_const;
            while (true) {
                var result = findWildcard(path) orelse break;
                if (!result.valid) {
                    @compileError("Only one wildcard per path segment is allowed, has: '" ++ result.wildcard ++ "' in path '" ++ full_path ++ "'");
                }

                if (result.wildcard.len < 2) {
                    @compileError("Wildcards must be named with a non-empty name in path '" ++ full_path ++ "'");
                }

                if (self.children.len > 0) {
                    @compileError("Wildcard segment '" ++ result.wildcard ++ "' conflicts with existing children in path '" ++ full_path ++ "'");
                }

                if (result.wildcard[0] == ':') {
                    if (result.start > 0) {
                        self.path = path[0..result.start];
                        path = path[result.start..];
                    }

                    self.wild_child = true;
                    var child: Self = .{
                        .label = .param,
                        .path = result.wildcard,
                    };
                    var children = [_]*Self{&child};
                    self.children = &children;
                    self = &child;
                    self.priority += 1;

                    if (result.wildcard.len < path.len) {
                        path = path[result.wildcard.len..];
                        var new_child: Self = .{ .priority = 1 };
                        var new_children = [_]*Self{&new_child};
                        self.children = &new_children;
                        self = &new_child;
                        continue;
                    }

                    self.value = value;
                    return;
                }

                if (result.start + result.wildcard.len != path.len) {
                    @compileError("Catch-all routes are only allowed at the end of the path in path '" ++ full_path ++ "'");
                }

                if (self.path.len > 0 and self.path[self.path.len - 1] == '/') {
                    @compileError("Catch-all conflicts with existing value for the path segment root in path '" ++ full_path ++ "'");
                }

                result.start -= 1;
                if (path[result.start] != '/') {
                    @compileError("No / before catch-all in path '" ++ full_path ++ "'");
                }

                self.path = path[0..result.start];

                var child: Self = .{
                    .wild_child = true,
                    .label = .catch_all,
                };
                var children = [_]*Self{&child};
                self.children = &children;
                self.indices = &[_]u8{'/'};
                self = &child;
                self.priority += 1;

                var child_leaf: Self = .{
                    .path = path[result.start..],
                    .label = .catch_all,
                    .value = value,
                    .priority = 1,
                };
                var new_children = [_]*Self{&child_leaf};
                self.children = &new_children;
                return;
            }
            self.path = path;
            self.value = value;
        }
    };
}

pub const Wildcard = struct {
    wildcard: []const u8,
    start: usize,
    valid: bool,
};

pub fn findWildcard(path: []const u8) ?Wildcard {
    for (path) |character, start| {
        if (character != ':' and character != '*') {
            continue;
        }
        var valid = true;
        for (path[start + 1 ..]) |other_character, end| {
            switch (other_character) {
                '/' => return Wildcard{ .wildcard = path[start .. start + 1 + end], .start = start, .valid = valid },
                ':', '*' => valid = false,
                else => {},
            }
        }
        return Wildcard{ .wildcard = path[start..], .start = start, .valid = valid };
    }
    return null;
}

pub fn countParams(path: []const u8) usize {
    var n: usize = 0;
    for (path) |character| {
        if (character == ':' or character == '*') {
            n += 1;
        }
    }
    return n;
}

pub fn longestCommonPrefix(a: []const u8, b: []const u8) usize {
    const max = math.min(a.len, b.len);

    var i: usize = 0;
    while (i < max and a[i] == b[i]) {
        i += 1;
    }
    return i;
}

test "Node" {
    const Walker = struct {
        pub fn next(key: []const u8, value: []const u8) void {
            testing.expectEqualStrings("world", key) catch unreachable;
            testing.expectEqualStrings("there", value) catch unreachable;
        }
    };

    const node = comptime build: {
        var node: Node(usize) = .{};
        node.put("/", 0);
        node.put("/hello", 1);
        node.put("/hello/:world", 2);
        node.put("/hello/:world/test", 3);
        break :build node;
    };

    try testing.expectEqual(Node(usize).GetResult{ .found = 0 }, node.get("/", Walker));
    try testing.expectEqual(Node(usize).GetResult{ .found = 1 }, node.get("/hello", Walker));
    try testing.expectEqual(Node(usize).GetResult{ .found = 2 }, node.get("/hello/there", Walker));

    try testing.expectEqual(Node(usize).GetResult{ .found = 3 }, node.get("/hello/there/test", Walker));
    try testing.expectEqual(Node(usize).GetResult.not_found, node.get("/hello/there/tes", Walker));
    try testing.expectEqual(Node(usize).GetResult.trailing_slash_redirect, node.get("/hello/there/test/", Walker));
}
