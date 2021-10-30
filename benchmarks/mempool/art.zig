const std = @import("std");

const mem = std.mem;
const testing = std.testing;

const Vector = std.meta.Vector;

fn keyAt(key: []const u8, index: usize) u8 {
    return if (index == key.len) 0 else key[index];
}

pub fn Tree(comptime V: type) type {
    return struct {
        pub const max_prefix_len = 10;

        pub const NodeType = enum(u2) {
            node_4,
            node_16,
            node_48,
            node_256,
        };

        pub const Node4 = Node(4, 4);
        pub const Node16 = Node(16, 16);
        pub const Node48 = Node(256, 48);
        pub const Node256 = Node(0, 256);

        pub fn RemoveChildMixin(comptime N: type) type {
            return if (N.num_keys == 0 and N.num_children == 256)
                struct {
                    pub fn removeChild(self: *N, gpa: *mem.Allocator, ref: *usize, character: u8) void {
                        self.children[character] = 0;
                        self.metadata.num_children -= 1;

                        if (self.metadata.num_children != 37) return;

                        const old_children = self.children;

                        const new_node = @ptrCast(*Node48, gpa.shrink(mem.span(mem.asBytes(self)), @sizeOf(Node48)).ptr);
                        new_node.metadata.node_type = .node_48;
                        ref.* = @ptrToInt(&new_node.metadata);

                        mem.set(u8, &new_node.keys, 0);
                        mem.set(usize, &new_node.children, 0);

                        var pos: u8 = 0;
                        comptime var i = 0;
                        inline while (i < old_children.len) : (i += 1) {
                            if (old_children[i] != 0) {
                                new_node.children[pos] = old_children[i];
                                new_node.keys[i] = pos + 1;
                                pos += 1;
                            }
                        }
                    }
                }
            else if (N.num_keys == 256 and N.num_children == 48)
                struct {
                    pub fn removeChild(self: *N, gpa: *mem.Allocator, ref: *usize, character: u8) void {
                        self.children[self.keys[character] - 1] = 0;
                        self.keys[character] = 0;

                        self.metadata.num_children -= 1;

                        if (self.metadata.num_children != 12) return;

                        const old_keys = self.keys;
                        const old_children = self.children;

                        const new_node = @ptrCast(*Node16, gpa.shrink(mem.span(mem.asBytes(self)), @sizeOf(Node16)).ptr);
                        new_node.metadata.node_type = .node_16;
                        ref.* = @ptrToInt(&new_node.metadata);

                        mem.set(u8, &new_node.keys, 0);
                        mem.set(usize, &new_node.children, 0);

                        var child: usize = 0;
                        comptime var i = 0;
                        inline while (i < old_keys.len) : (i += 1) {
                            if (old_keys[i] != 0) {
                                new_node.keys[child] = i;
                                new_node.children[child] = old_children[old_keys[i] - 1];
                                child += 1;
                            }
                        }
                    }
                }
            else if (N.num_keys == 16 and N.num_children == 16)
                struct {
                    pub fn removeChild(self: *N, gpa: *mem.Allocator, ref: *usize, leaf: *usize) void {
                        const pos = (@ptrToInt(leaf) - @ptrToInt(&self.children)) / @sizeOf(usize);
                        mem.copy(u8, self.keys[pos..], self.keys[pos + 1 ..][0 .. self.metadata.num_children - 1 - pos]);
                        mem.copy(usize, self.children[pos..], self.children[pos + 1 ..][0 .. self.metadata.num_children - 1 - pos]);
                        self.metadata.num_children -= 1;

                        if (self.metadata.num_children != 3) return;

                        const old_keys = self.keys;
                        const old_children = self.children;

                        const new_node = @ptrCast(*Node4, gpa.shrink(mem.span(mem.asBytes(self)), @sizeOf(Node4)).ptr);
                        new_node.metadata.node_type = .node_4;
                        ref.* = @ptrToInt(&new_node.metadata);

                        mem.set(u8, &new_node.keys, 0);
                        mem.set(usize, &new_node.children, 0);

                        mem.copy(u8, &new_node.keys, old_keys[0..new_node.keys.len]);
                        mem.copy(usize, &new_node.children, old_children[0..new_node.children.len]);
                    }
                }
            else if (N.num_keys == 4 and N.num_children == 4)
                struct {
                    pub fn removeChild(self: *N, gpa: *mem.Allocator, ref: *usize, leaf: *usize) void {
                        const pos = (@ptrToInt(leaf) - @ptrToInt(&self.children)) / @sizeOf(usize);
                        mem.copy(u8, self.keys[pos..], self.keys[pos + 1 ..][0 .. self.metadata.num_children - 1 - pos]);
                        mem.copy(usize, self.children[pos..], self.children[pos + 1 ..][0 .. self.metadata.num_children - 1 - pos]);
                        self.metadata.num_children -= 1;

                        if (self.metadata.num_children != 1) return;

                        const child = self.children[0];
                        if (Leaf.from(child) == null) {
                            var prefix = self.metadata.partial_len;
                            if (prefix < max_prefix_len) {
                                self.metadata.partial[prefix] = self.keys[0];
                                prefix += 1;
                            }
                            const child_node = @intToPtr(*Metadata, child);
                            if (prefix < max_prefix_len) {
                                const sub_prefix = @minimum(child_node.partial_len, max_prefix_len - prefix);
                                mem.copy(u8, self.metadata.partial[prefix..], child_node.partial[0..sub_prefix]);
                                prefix += sub_prefix;
                            }

                            mem.copy(u8, &child_node.partial, self.metadata.partial[0..@minimum(prefix, max_prefix_len)]);
                            child_node.partial_len += self.metadata.partial_len + 1;
                        }
                        ref.* = child;
                        gpa.destroy(self);
                    }
                }
            else
                @compileError("unknown node configuration");
        }

        pub fn AddChildMixin(comptime N: type) type {
            return if (N.num_keys == 0 and N.num_children == 256)
                struct {
                    pub fn addChild(self: *N, gpa: *mem.Allocator, ref: *usize, character: u8, child: usize) !void {
                        _ = gpa;
                        _ = ref;
                        self.children[character] = child;
                        self.metadata.num_children += 1;
                    }
                }
            else if (N.num_keys == 256 and N.num_children == 48)
                struct {
                    pub fn addChild(self: *N, gpa: *mem.Allocator, ref: *usize, character: u8, child: usize) !void {
                        if (self.metadata.num_children < self.children.len) {
                            const pos = @intCast(u8, mem.indexOfScalar(usize, &self.children, 0).?);
                            self.children[pos] = child;
                            self.keys[character] = pos + 1;
                            self.metadata.num_children += 1;
                            return;
                        }

                        const old_keys = self.keys;
                        const old_children = self.children;

                        const new_node = @ptrCast(*Node256, (try gpa.realloc(mem.span(mem.asBytes(self)), @sizeOf(Node256))).ptr);
                        new_node.metadata.node_type = .node_256;

                        mem.set(usize, &new_node.children, 0);

                        comptime var i = 0;
                        inline while (i < old_keys.len) : (i += 1) {
                            if (old_keys[i] != 0) {
                                new_node.children[i] = old_children[old_keys[i] - 1];
                            }
                        }

                        ref.* = @ptrToInt(&new_node.metadata);
                        try new_node.addChild(gpa, ref, character, child);
                    }
                }
            else if (N.num_keys == 16 and N.num_children == 16)
                struct {
                    pub fn addChild(self: *N, gpa: *mem.Allocator, ref: *usize, character: u8, child: usize) !void {
                        if (self.metadata.num_children < self.children.len) {
                            const cmp = @splat(16, character) < @as(Vector(16, u8), self.keys);
                            const mask = (@as(u17, 1) << @intCast(u5, self.metadata.num_children)) - 1;
                            const bitfield = @ptrCast(*const u17, &cmp).* & mask;
                            const idx = idx: {
                                if (bitfield != 0) {
                                    const idx = @ctz(usize, bitfield);
                                    const shift_len = self.metadata.num_children - idx;
                                    mem.copyBackwards(u8, self.keys[idx + 1 ..], self.keys[idx..][0..shift_len]);
                                    mem.copyBackwards(usize, self.children[idx + 1 ..], self.children[idx..][0..shift_len]);
                                    break :idx idx;
                                }
                                break :idx self.metadata.num_children;
                            };

                            self.keys[idx] = character;
                            self.children[idx] = child;
                            self.metadata.num_children += 1;
                            return;
                        }

                        const old_keys = self.keys;
                        const old_children = self.children;

                        const new_node = @ptrCast(*Node48, (try gpa.realloc(mem.span(mem.asBytes(self)), @sizeOf(Node48))).ptr);
                        new_node.metadata.node_type = .node_48;

                        mem.set(u8, &new_node.keys, 0);
                        mem.set(usize, &new_node.children, 0);

                        mem.copy(usize, &new_node.children, &old_children);

                        comptime var i: u8 = 0;
                        inline while (i < old_children.len) : (i += 1) {
                            new_node.keys[old_keys[i]] = i + 1;
                        }

                        ref.* = @ptrToInt(&new_node.metadata);
                        try new_node.addChild(gpa, ref, character, child);
                    }
                }
            else if (N.num_keys == 4 and N.num_children == 4)
                struct {
                    pub fn addChild(self: *N, gpa: *mem.Allocator, ref: *usize, character: u8, child: usize) !void {
                        if (self.metadata.num_children < self.children.len) {
                            const idx = for (self.keys[0..self.metadata.num_children]) |key, i| {
                                if (character < key) break i;
                            } else self.metadata.num_children;

                            const shift_len = self.metadata.num_children - idx;
                            mem.copyBackwards(u8, self.keys[idx + 1 ..], self.keys[idx..][0..shift_len]);
                            mem.copyBackwards(usize, self.children[idx + 1 ..], self.children[idx..][0..shift_len]);

                            self.keys[idx] = character;
                            self.children[idx] = child;
                            self.metadata.num_children += 1;
                            return;
                        }

                        const old_keys = self.keys;
                        const old_children = self.children;

                        const new_node = @ptrCast(*Node16, (try gpa.realloc(mem.span(mem.asBytes(self)), @sizeOf(Node16))).ptr);
                        new_node.metadata.node_type = .node_16;

                        mem.set(u8, &new_node.keys, 0);
                        mem.set(usize, &new_node.children, 0);

                        mem.copy(u8, &new_node.keys, &old_keys);
                        mem.copy(usize, &new_node.children, &old_children);

                        ref.* = @ptrToInt(&new_node.metadata);
                        try new_node.addChild(gpa, ref, character, child);
                    }
                }
            else
                @compileError("unknown node configuration");
        }

        pub fn Node(comptime num_keys_: comptime_int, comptime num_children_: comptime_int) type {
            return struct {
                pub const num_keys = num_keys_;
                pub const num_children = num_children_;

                metadata: Metadata,
                keys: [num_keys]u8 = [_]u8{0} ** num_keys,
                children: [num_children]usize = [_]usize{0} ** num_children,

                pub usingnamespace AddChildMixin(@This());
                pub usingnamespace RemoveChildMixin(@This());
            };
        }

        pub const Metadata = struct {
            partial_len: u8 = 0,
            node_type: NodeType,
            num_children: u9 = 0,
            partial: [max_prefix_len]u8 = undefined,

            pub fn init(gpa: *mem.Allocator, node_type: NodeType) !*Metadata {
                switch (node_type) {
                    .node_4 => {
                        const node = try gpa.create(Node4);
                        node.* = .{ .metadata = .{ .node_type = node_type } };
                        return &node.metadata;
                    },
                    .node_16 => {
                        const node = try gpa.create(Node16);
                        node.* = .{ .metadata = .{ .node_type = node_type } };
                        return &node.metadata;
                    },
                    .node_48 => {
                        const node = try gpa.create(Node48);
                        node.* = .{ .metadata = .{ .node_type = node_type } };
                        return &node.metadata;
                    },
                    .node_256 => {
                        const node = try gpa.create(Node256);
                        node.* = .{ .metadata = .{ .node_type = node_type } };
                        return &node.metadata;
                    },
                }
            }

            pub fn deinit(self: *Metadata, gpa: *mem.Allocator) void {
                @setEvalBranchQuota(10_000);

                switch (self.node_type) {
                    .node_4 => {
                        const node = @fieldParentPtr(Node4, "metadata", self);
                        for (node.children[0..self.num_children]) |child| {
                            if (child != 0) {
                                if (Leaf.from(child)) |leaf_node| {
                                    leaf_node.deinit(gpa);
                                } else {
                                    @intToPtr(*Metadata, child).deinit(gpa);
                                }
                            }
                        }
                        return gpa.destroy(node);
                    },
                    .node_16 => {
                        const node = @fieldParentPtr(Node16, "metadata", self);
                        for (node.children[0..self.num_children]) |child| {
                            if (child != 0) {
                                if (Leaf.from(child)) |leaf_node| {
                                    leaf_node.deinit(gpa);
                                } else {
                                    @intToPtr(*Metadata, child).deinit(gpa);
                                }
                            }
                        }
                        return gpa.destroy(node);
                    },
                    .node_48 => {
                        const node = @fieldParentPtr(Node48, "metadata", self);
                        comptime var i: usize = 0;
                        inline while (i < node.children.len) : (i += 1) {
                            if (node.children[i] != 0) {
                                if (Leaf.from(node.children[i])) |leaf_node| {
                                    leaf_node.deinit(gpa);
                                } else {
                                    @intToPtr(*Metadata, node.children[i]).deinit(gpa);
                                }
                            }
                        }
                        return gpa.destroy(node);
                    },
                    .node_256 => {
                        const node = @fieldParentPtr(Node256, "metadata", self);
                        comptime var i: usize = 0;
                        inline while (i < node.children.len) : (i += 1) {
                            if (node.children[i] != 0) {
                                if (Leaf.from(node.children[i])) |leaf_node| {
                                    leaf_node.deinit(gpa);
                                } else {
                                    @intToPtr(*Metadata, node.children[i]).deinit(gpa);
                                }
                            }
                        }
                        return gpa.destroy(node);
                    },
                }
            }

            pub fn addChild(self: *Metadata, gpa: *mem.Allocator, ref: *usize, character: u8, child: usize) !void {
                return switch (self.node_type) {
                    .node_4 => @fieldParentPtr(Node4, "metadata", self).addChild(gpa, ref, character, child),
                    .node_16 => @fieldParentPtr(Node16, "metadata", self).addChild(gpa, ref, character, child),
                    .node_48 => @fieldParentPtr(Node48, "metadata", self).addChild(gpa, ref, character, child),
                    .node_256 => @fieldParentPtr(Node256, "metadata", self).addChild(gpa, ref, character, child),
                };
            }

            pub fn removeChild(self: *Metadata, gpa: *mem.Allocator, ref: *usize, character: u8, leaf: *usize) void {
                return switch (self.node_type) {
                    .node_4 => @fieldParentPtr(Node4, "metadata", self).removeChild(gpa, ref, leaf),
                    .node_16 => @fieldParentPtr(Node16, "metadata", self).removeChild(gpa, ref, leaf),
                    .node_48 => @fieldParentPtr(Node48, "metadata", self).removeChild(gpa, ref, character),
                    .node_256 => @fieldParentPtr(Node256, "metadata", self).removeChild(gpa, ref, character),
                };
            }

            pub fn findChild(self: *Metadata, character: u8) ?*usize {
                switch (self.node_type) {
                    .node_4 => {
                        const node = @fieldParentPtr(Node4, "metadata", self);
                        if (mem.indexOfScalar(u8, node.keys[0..self.num_children], character)) |index| {
                            return &node.children[index];
                        }
                    },
                    .node_16 => {
                        const node = @fieldParentPtr(Node16, "metadata", self);
                        const cmp = @as(Vector(16, u8), node.keys) == @splat(16, character);
                        const child_index = @ctz(usize, @ptrCast(*const u16, &cmp).*);
                        if (child_index < self.num_children) return &node.children[child_index];
                    },
                    .node_48 => {
                        const node = @fieldParentPtr(Node48, "metadata", self);
                        if (node.keys[character] != 0) return &node.children[node.keys[character] - 1];
                    },
                    .node_256 => {
                        const node = @fieldParentPtr(Node256, "metadata", self);
                        if (node.children[character] != 0) return &node.children[character];
                    },
                }
                return null;
            }

            pub fn checkPrefix(self: *Metadata, key: []const u8, depth: usize) usize {
                const max_cmp = @minimum(@minimum(self.partial_len, max_prefix_len), key.len - depth);
                return mem.indexOfDiff(u8, self.partial[0..max_cmp], key[depth..][0..max_cmp]) orelse max_cmp;
            }

            pub fn prefixMismatch(self: *Metadata, key: []const u8, depth: usize) usize {
                const max_cmp = @minimum(@minimum(max_prefix_len, self.partial_len), key.len - depth);
                if (mem.indexOfDiff(u8, self.partial[0..max_cmp], key[depth..][0..max_cmp])) |diff_index| {
                    return diff_index;
                }
                if (self.partial_len > max_prefix_len) {
                    const leaf_node = Metadata.minimum(@ptrToInt(self)) orelse unreachable;
                    const leaf_max_cmp = @minimum(leaf_node.key_len, key.len) - depth;
                    if (mem.indexOfDiff(u8, leaf_node.keySlice()[max_cmp..][depth..][0..leaf_max_cmp], key[max_cmp..][depth..][0..leaf_max_cmp])) |diff_index| {
                        return diff_index;
                    }
                    return leaf_max_cmp;
                }
                return max_cmp;
            }

            pub fn minimum(ptr: usize) ?*Leaf {
                if (ptr == 0) {
                    return null;
                }

                if (Leaf.from(ptr)) |leaf| {
                    return leaf;
                }

                @setEvalBranchQuota(2000);

                const metadata = @intToPtr(*Metadata, ptr);
                switch (metadata.node_type) {
                    .node_4 => return minimum(@fieldParentPtr(Node4, "metadata", metadata).children[0]),
                    .node_16 => return minimum(@fieldParentPtr(Node16, "metadata", metadata).children[0]),
                    .node_48 => {
                        const node = @fieldParentPtr(Node48, "metadata", metadata);
                        comptime var i: usize = 0;
                        inline while (i < node.keys.len) : (i += 1) {
                            if (node.keys[i] != 0) {
                                return minimum(node.children[node.keys[i] - 1]);
                            }
                        }
                        unreachable;
                    },
                    .node_256 => {
                        const node = @fieldParentPtr(Node256, "metadata", metadata);
                        comptime var i: usize = 0;
                        inline while (i < node.children.len) : (i += 1) {
                            if (node.children[i] != 0) {
                                return minimum(node.children[i]);
                            }
                        }
                        unreachable;
                    },
                }
            }

            pub fn maximum(ptr: usize) ?*Leaf {
                if (ptr == 0) {
                    return null;
                }

                if (Leaf.from(ptr)) |leaf| {
                    return leaf;
                }

                @setEvalBranchQuota(2000);

                const metadata = @intToPtr(*Metadata, ptr);
                switch (metadata.node_type) {
                    .node_4 => return maximum(@fieldParentPtr(Node4, "metadata", metadata).children[metadata.num_children - 1]),
                    .node_16 => return maximum(@fieldParentPtr(Node16, "metadata", metadata).children[metadata.num_children - 1]),
                    .node_48 => {
                        const node = @fieldParentPtr(Node48, "metadata", metadata);
                        comptime var i: usize = node.keys.len - 1;
                        inline while (i > 0) : (i -= 1) {
                            if (node.keys[i - 1] != 0) {
                                return maximum(node.children[node.keys[i - 1] - 1]);
                            }
                        }
                        unreachable;
                    },
                    .node_256 => {
                        const node = @fieldParentPtr(Node256, "metadata", metadata);
                        comptime var i: usize = node.children.len - 1;
                        inline while (i > 0) : (i -= 1) {
                            if (node.children[i - 1] != 0) {
                                return maximum(node.children[i - 1]);
                            }
                        }
                        unreachable;
                    },
                }
            }

            pub fn delete(self: usize, gpa: *mem.Allocator, ref: *usize, key: []const u8, depth_const: usize) ?*Leaf {
                if (self == 0) {
                    return null;
                }

                if (Leaf.from(self)) |leaf_node| {
                    if (mem.eql(u8, leaf_node.keySlice(), key)) {
                        ref.* = 0;
                        return leaf_node;
                    }
                    return null;
                }

                var depth = depth_const;

                const node = @intToPtr(*Metadata, self);
                if (node.partial_len != 0) {
                    const prefix_len = node.checkPrefix(key, depth);
                    if (prefix_len != @minimum(max_prefix_len, node.partial_len)) {
                        return null;
                    }
                    depth += node.partial_len;
                }

                const child = node.findChild(keyAt(key, depth)) orelse return null;
                if (Leaf.from(child.*)) |leaf_node| {
                    if (mem.eql(u8, leaf_node.keySlice(), key)) {
                        node.removeChild(gpa, ref, keyAt(key, depth), child);
                        return leaf_node;
                    }
                    return null;
                }

                return Metadata.delete(child.*, gpa, child, key, depth + 1);
            }

            pub fn insert(self: usize, gpa: *mem.Allocator, ref: *usize, key: []const u8, value: V, depth: usize, old: *bool, replace: bool) !if (V == void) V else ?V {
                if (self == 0) {
                    const leaf_node = try Leaf.init(gpa, key, value);
                    ref.* = @ptrToInt(leaf_node) | 1;
                    return if (V == void) {} else null;
                }

                if (Leaf.from(self)) |leaf_node| {
                    if (mem.eql(u8, leaf_node.keySlice(), key)) {
                        old.* = true;
                        const old_value = leaf_node.value;
                        if (replace) leaf_node.value = value;
                        return old_value;
                    }

                    const new_node_metadata = try Metadata.init(gpa, .node_4);
                    errdefer new_node_metadata.deinit(gpa);

                    const new_node = @fieldParentPtr(Node4, "metadata", new_node_metadata);

                    const new_leaf_node = try Leaf.init(gpa, key, value);
                    errdefer new_leaf_node.deinit(gpa);

                    const longest_prefix = leaf_node.longestCommonPrefix(new_leaf_node, depth);
                    new_node_metadata.partial_len = @intCast(u8, longest_prefix);
                    mem.copy(u8, &new_node_metadata.partial, key[depth..][0..@minimum(max_prefix_len, longest_prefix)]);

                    ref.* = @ptrToInt(new_node_metadata);
                    errdefer ref.* = 0;

                    try new_node.addChild(gpa, ref, keyAt(leaf_node.keySlice(), depth + longest_prefix), @ptrToInt(leaf_node) | 1);
                    try new_node.addChild(gpa, ref, keyAt(new_leaf_node.keySlice(), depth + longest_prefix), @ptrToInt(new_leaf_node) | 1);
                    return if (V == void) {} else null;
                }

                const node = @intToPtr(*Metadata, self);
                if (node.partial_len != 0) {
                    const prefix_diff = node.prefixMismatch(key, depth);
                    if (prefix_diff >= node.partial_len) {
                        return node.insertRecursiveSearch(gpa, ref, key, value, depth + node.partial_len, old, replace);
                    }

                    const new_node_metadata = try Metadata.init(gpa, .node_4);
                    errdefer new_node_metadata.deinit(gpa);

                    ref.* = @ptrToInt(new_node_metadata);
                    errdefer ref.* = 0;

                    const new_node = @fieldParentPtr(Node4, "metadata", new_node_metadata);

                    new_node_metadata.partial_len = @intCast(u8, prefix_diff);
                    mem.copy(u8, &new_node_metadata.partial, node.partial[0..@minimum(max_prefix_len, prefix_diff)]);

                    if (node.partial_len <= max_prefix_len) {
                        try new_node.addChild(gpa, ref, keyAt(&node.partial, prefix_diff), @ptrToInt(node));
                        node.partial_len -= @intCast(u8, prefix_diff + 1);
                        mem.copy(u8, &node.partial, node.partial[prefix_diff + 1 ..][0..@minimum(max_prefix_len, node.partial_len)]);
                    } else {
                        node.partial_len -= @intCast(u8, prefix_diff + 1);
                        const leaf_node = Metadata.minimum(self) orelse unreachable;
                        try new_node.addChild(gpa, ref, keyAt(leaf_node.keySlice(), depth + prefix_diff), @ptrToInt(node));
                        mem.copy(u8, &node.partial, leaf_node.keySlice()[depth + prefix_diff + 1 ..][0..@minimum(max_prefix_len, node.partial_len)]);
                    }

                    const new_leaf_node = try Leaf.init(gpa, key, value);
                    errdefer new_leaf_node.deinit(gpa);

                    try new_node.addChild(gpa, ref, keyAt(new_leaf_node.keySlice(), depth + prefix_diff), @ptrToInt(new_leaf_node) | 1);

                    return if (V == void) {} else null;
                }

                return node.insertRecursiveSearch(gpa, ref, key, value, depth, old, replace);
            }

            fn insertRecursiveSearch(self: *Metadata, gpa: *mem.Allocator, ref: *usize, key: []const u8, value: V, depth: usize, old: *bool, replace: bool) anyerror!if (V == void) V else ?V {
                if (self.findChild(keyAt(key, depth))) |child| {
                    return Metadata.insert(child.*, gpa, child, key, value, depth + 1, old, replace);
                }

                const new_leaf_node = try Leaf.init(gpa, key, value);
                errdefer new_leaf_node.deinit(gpa);

                try self.addChild(gpa, ref, keyAt(new_leaf_node.keySlice(), depth), @ptrToInt(new_leaf_node) | 1);

                return if (V == void) {} else null;
            }
        };

        pub const Leaf = struct {
            value: V,
            key_len: u32,

            pub fn init(gpa: *mem.Allocator, key: []const u8, value: V) !*Leaf {
                const bytes = try gpa.allocAdvanced(u8, @alignOf(Leaf), @sizeOf(Leaf) + key.len, .exact);
                mem.copy(u8, bytes[@sizeOf(Leaf)..], key);

                const leaf = @intToPtr(*Leaf, @ptrToInt(bytes.ptr));
                leaf.* = .{ .value = value, .key_len = @intCast(u32, key.len) };

                return leaf;
            }

            pub fn from(ptr: usize) ?*Leaf {
                if (ptr & 1 != 0) {
                    return @intToPtr(*Leaf, ptr & ~@as(usize, 1));
                }
                return null;
            }

            pub fn deinit(self: *Leaf, gpa: *mem.Allocator) void {
                const bytes = @ptrCast([*]u8, self)[0 .. @sizeOf(Leaf) + self.key_len];
                return gpa.free(bytes);
            }

            pub fn keySlice(self: *Leaf) []const u8 {
                return (@ptrCast([*]u8, self) + @sizeOf(Leaf))[0..self.key_len];
            }

            pub fn longestCommonPrefix(self: *Leaf, other: *Leaf, depth: usize) usize {
                const max_cmp = @minimum(self.key_len, other.key_len) - depth;
                return mem.indexOfDiff(u8, self.keySlice()[depth..][0..max_cmp], other.keySlice()[depth..][0..max_cmp]) orelse max_cmp;
            }
        };

        const Self = @This();

        root: usize = 0,
        size: u64 = 0,

        pub fn deinit(self: *const Self, gpa: *mem.Allocator) void {
            if (self.root == 0) return;
            if (Leaf.from(self.root)) |leaf_node| return leaf_node.deinit(gpa);
            return @intToPtr(*Metadata, self.root).deinit(gpa);
        }

        pub fn minimum(self: *const Self) ?*Leaf {
            return Metadata.minimum(self.root);
        }

        pub fn maximum(self: *const Self) ?*Leaf {
            return Metadata.maximum(self.root);
        }

        pub fn search(self: *const Self, key: []const u8) ?V {
            var it = self.root;
            var depth: usize = 0;
            while (it != 0) : (depth += 1) {
                if (Leaf.from(it)) |leaf| {
                    if (mem.eql(u8, leaf.keySlice(), key)) {
                        return leaf.value;
                    }
                    return null;
                }

                const node = @intToPtr(*Metadata, it);

                if (node.partial_len != 0) {
                    const prefix_len = node.checkPrefix(key, depth);
                    if (prefix_len != @minimum(max_prefix_len, node.partial_len)) {
                        return null;
                    }
                    depth += node.partial_len;
                }

                if (node.findChild(keyAt(key, depth))) |child| {
                    it = child.*;
                    continue;
                }
                break;
            }
            return null;
        }

        pub fn insert(self: *Self, gpa: *mem.Allocator, key: []const u8, value: V) !if (V == void) V else ?V {
            var is_old = false;
            const old = try Metadata.insert(self.root, gpa, &self.root, key, value, 0, &is_old, true);
            if (!is_old) self.size += 1;
            return old;
        }

        pub fn delete(self: *Self, gpa: *mem.Allocator, key: []const u8) if (V == void) V else ?V {
            if (Metadata.delete(self.root, gpa, &self.root, key, 0)) |leaf_node| {
                self.size -= 1;
                const value = leaf_node.value;
                leaf_node.deinit(gpa);
                return value;
            }
            return if (V == void) {} else null;
        }

        pub fn iterateNodes(self: *Self, closure: anytype) void {
            _ = self.iterateNodesRecursive(self.root, 0, closure);
        }

        fn iterateNodesRecursive(self: *Self, it: usize, depth: usize, closure: anytype) bool {
            if (it == 0) {
                return closure.run(it, depth);
            }

            if (Leaf.from(it) != null) {
                return closure.run(it, depth);
            }

            @setEvalBranchQuota(2000);

            const metadata = @intToPtr(*Metadata, it);
            if (!closure.run(it, depth)) {
                return false;
            }
            switch (metadata.node_type) {
                .node_4 => {
                    const node = @fieldParentPtr(Node4, "metadata", metadata);
                    for (node.children[0..metadata.num_children]) |child| {
                        if (!self.iterateNodesRecursive(child, depth + 1, closure)) {
                            return false;
                        }
                    }
                },
                .node_16 => {
                    const node = @fieldParentPtr(Node16, "metadata", metadata);
                    for (node.children[0..metadata.num_children]) |child| {
                        if (!self.iterateNodesRecursive(child, depth + 1, closure)) {
                            return false;
                        }
                    }
                },
                .node_48 => {
                    const node = @fieldParentPtr(Node48, "metadata", metadata);
                    comptime var i: usize = 0;
                    inline while (i < node.keys.len) : (i += 1) {
                        if (node.keys[i] != 0) {
                            if (!self.iterateNodesRecursive(node.children[node.keys[i] - 1], depth + 1, closure)) {
                                return false;
                            }
                        }
                    }
                },
                .node_256 => {
                    const node = @fieldParentPtr(Node256, "metadata", metadata);
                    comptime var i: usize = 0;
                    inline while (i < node.children.len) : (i += 1) {
                        if (node.children[i] != 0) {
                            if (!self.iterateNodesRecursive(node.children[i], depth + 1, closure)) {
                                return false;
                            }
                        }
                    }
                },
            }
            return true;
        }

        pub fn iterate(self: *Self, closure: anytype) void {
            _ = self.iterateRecursive(self.root, closure);
        }

        fn iterateRecursive(self: *Self, it: usize, closure: anytype) bool {
            if (it == 0) {
                return true;
            }

            if (Leaf.from(it)) |leaf| {
                return closure.run(leaf.keySlice(), leaf.value);
            }

            @setEvalBranchQuota(2000);

            const metadata = @intToPtr(*Metadata, it);
            switch (metadata.node_type) {
                .node_4 => {
                    const node = @fieldParentPtr(Node4, "metadata", metadata);
                    for (node.children[0..metadata.num_children]) |child| {
                        if (!self.iterateRecursive(child, closure)) {
                            return false;
                        }
                    }
                },
                .node_16 => {
                    const node = @fieldParentPtr(Node16, "metadata", metadata);
                    for (node.children[0..metadata.num_children]) |child| {
                        if (!self.iterateRecursive(child, closure)) {
                            return false;
                        }
                    }
                },
                .node_48 => {
                    const node = @fieldParentPtr(Node48, "metadata", metadata);
                    comptime var i: usize = 0;
                    inline while (i < node.keys.len) : (i += 1) {
                        if (node.keys[i] != 0) {
                            if (!self.iterateRecursive(node.children[node.keys[i] - 1], closure)) {
                                return false;
                            }
                        }
                    }
                },
                .node_256 => {
                    const node = @fieldParentPtr(Node256, "metadata", metadata);
                    comptime var i: usize = 0;
                    inline while (i < node.children.len) : (i += 1) {
                        if (node.children[i] != 0) {
                            if (!self.iterateRecursive(node.children[i], closure)) {
                                return false;
                            }
                        }
                    }
                },
            }

            return true;
        }

        pub fn print(it: usize, depth: usize) bool {
            const spaces = [_]u8{' '} ** 256;

            if (it == 0) {
                std.debug.print("empty\n", .{});
                return true;
            }

            if (Leaf.from(it)) |leaf| {
                std.debug.print("{s}-> {s} = {}\n", .{ spaces[0 .. depth * 2], leaf.keySlice(), leaf.value });
                return true;
            }

            const metadata = @intToPtr(*Metadata, it);
            switch (metadata.node_type) {
                .node_4 => {
                    const node = @fieldParentPtr(Node4, "metadata", metadata);
                    std.debug.print("{s}4   [{s}] ({s}) {} children\n", .{
                        spaces[0 .. depth * 2],
                        node.keys,
                        metadata.partial[0..@minimum(max_prefix_len, metadata.partial_len)],
                        @as(u16, metadata.num_children),
                    });
                },
                .node_16 => {
                    const node = @fieldParentPtr(Node16, "metadata", metadata);
                    std.debug.print("{s}16  [{s}] ({s}) {} children\n", .{
                        spaces[0 .. depth * 2],
                        node.keys,
                        metadata.partial[0..@minimum(max_prefix_len, metadata.partial_len)],
                        @as(u16, metadata.num_children),
                    });
                },
                .node_48 => {
                    const node = @fieldParentPtr(Node48, "metadata", metadata);
                    std.debug.print("{s}48  [", .{spaces[0 .. depth * 2]});
                    for (node.keys) |character, i| {
                        if (character != 0) {
                            std.debug.print("{c}", .{@intCast(u8, i)});
                        }
                    }
                    std.debug.print("] ({s}) {} children\n", .{ metadata.partial[0..@minimum(max_prefix_len, metadata.partial_len)], @as(u16, metadata.num_children) });
                },
                .node_256 => {
                    const node = @fieldParentPtr(Node256, "metadata", metadata);
                    std.debug.print("{s}256 [", .{spaces[0 .. depth * 2]});
                    for (node.children) |child, i| {
                        if (child != 0) {
                            std.debug.print("{c}", .{@intCast(u8, i)});
                        }
                    }
                    std.debug.print("] ({s}) {} children\n", .{ metadata.partial[0..@minimum(max_prefix_len, metadata.partial_len)], @as(u16, metadata.num_children) });
                },
            }

            return true;
        }
    };
}

test {
    testing.refAllDecls(Tree(void));
    testing.refAllDecls(Tree(void).Metadata);
    testing.refAllDecls(Tree(void).Leaf);
    testing.refAllDecls(Tree(void).Node4);
    testing.refAllDecls(Tree(void).Node16);
    testing.refAllDecls(Tree(void).Node48);
    testing.refAllDecls(Tree(void).Node256);
}

test "node16 simd" {
    const characters: [16]u8 = .{ 'a', 'b', 'c', 'd', 'e', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r' };

    var cmp_eq = @as(Vector(16, u8), characters) == @splat(16, @as(u8, 'e'));
    try testing.expectEqual(@as(usize, 4), @ctz(u16, @ptrCast(*const u16, &cmp_eq).*));

    var cmp_le = @as(Vector(16, u8), characters) < @splat(16, @as(u8, 'f'));
    try testing.expectEqual(@as(usize, 5), @popCount(u16, @ptrCast(*const u16, &cmp_le).*));
    try testing.expectEqual(@as(usize, 5), 16 - @clz(u16, @ptrCast(*const u16, &cmp_le).*));

    var cmp_le2 = @as(Vector(16, u8), characters) < @splat(16, @as(u8, 'z'));
    try testing.expectEqual(@as(usize, 16), @popCount(u16, @ptrCast(*const u16, &cmp_le2).*));
    try testing.expectEqual(@as(usize, 16), 16 - @clz(u16, @ptrCast(*const u16, &cmp_le2).*));
}

test "insert" {
    var tree: Tree(void) = .{};
    defer tree.deinit(testing.allocator);

    try tree.insert(testing.allocator, "hello", {});
    try testing.expectEqual(@as(?void, {}), tree.search("hello"));
    try testing.expectEqual(@as(?void, null), tree.search("hello world"));
    try tree.insert(testing.allocator, "hello world", {});
    try testing.expectEqual(@as(?void, {}), tree.search("hello"));
    try testing.expectEqual(@as(?void, {}), tree.search("hello world"));
}

test "stress insert" {
    const tree_size: usize = 5000;

    var tree: Tree(*c_void) = .{};
    defer tree.deinit(testing.allocator);

    var rng = std.rand.DefaultPrng.init(1);

    var keys = try testing.allocator.alloc([32:0]u8, tree_size);
    defer testing.allocator.free(keys);

    for (keys) |*key| {
        for (key) |*c| c.* = rng.random().intRangeAtMost(u8, 'A', 'z');
        key[32] = 0;
    }

    for (keys) |*key| {
        _ = try tree.insert(testing.allocator, key, @intToPtr(*c_void, 0xdeadbeef));
    }

    try testing.expectEqual(tree_size, tree.size);
}
