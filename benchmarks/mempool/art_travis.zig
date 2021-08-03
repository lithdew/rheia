const std = @import("std");
const mem = std.mem;
const math = std.math;

const warn = std.debug.warn;

pub fn Art(comptime T: type) type {
    return struct {
        root: *Node,
        size: usize,
        allocator: *std.mem.Allocator,

        const Tree = @This();
        const MaxPrefixLen = 10;
        const BaseNode = struct {
            num_children: u9,
            partial_len: u8,
            partial: [MaxPrefixLen]u8 = [1]u8{0} ** MaxPrefixLen,
        };
        fn SizedNode(comptime _num_keys: usize, comptime _num_children: usize) type {
            const num_keys_adj = if (_num_keys == 0) 1 else _num_keys;
            return struct {
                num_children: u9,
                partial_len: u8,
                partial: [MaxPrefixLen]u8 = [1]u8{0} ** MaxPrefixLen,
                keys: *[num_keys_adj]u8,
                children: *[num_children]*Node,
                const Self = @This();
                pub const num_keys = num_keys_adj;
                pub const num_children = _num_children;
                pub fn baseNode(self: *Self) *BaseNode {
                    return @ptrCast(*BaseNode, self);
                }
            };
        }
        pub const Leaf = struct {
            value: T,
            key: []const u8,
        };
        pub const Node4 = SizedNode(4, 4);
        pub const Node16 = SizedNode(16, 16);
        pub const Node48 = SizedNode(256, 48);
        pub const Node256 = SizedNode(0, 256);
        pub const Node = union(enum) {
            empty,
            leaf: Leaf,
            node4: Node4,
            node16: Node16,
            node48: Node48,
            node256: Node256,

            pub fn baseNode(n: *Node) *BaseNode {
                return switch (n.*) {
                    .node4 => n.*.node4.baseNode(),
                    .node16 => n.*.node16.baseNode(),
                    .node48 => n.*.node48.baseNode(),
                    .node256 => n.*.node256.baseNode(),
                    .leaf, .empty => unreachable,
                };
            }

            pub fn childIterator(n: *Node) ChildIterator {
                return ChildIterator{ .i = 0, .parent = n };
            }
            pub const ChildIterator = struct {
                i: u9,
                parent: *Node,

                pub fn next(self: *ChildIterator) ?*Node {
                    return switch (self.parent.*) {
                        .node4 => self.yieldNext(self.parent.node4, 4, bodyGeneral),
                        .node16 => self.yieldNext(self.parent.node16, 16, bodyGeneral),
                        .node48 => self.yieldNext(self.parent.node48, 256, body48),
                        .node256 => self.yieldNext(self.parent.node256, 256, bodyGeneral),
                        .leaf, .empty => unreachable,
                    };
                }
                fn yieldNext(self: *ChildIterator, node: anytype, max: u9, loopBody: fn (self: *ChildIterator, parent: anytype) bool) ?*Node {
                    if (self.i == max) return null;
                    defer self.i += 1;
                    while (true) : (self.i += 1) {
                        if (loopBody(self, node)) |n| return n;
                        if (self.i == max - 1) break;
                    }
                    return null;
                }
                fn bodyGeneral(_self: *ChildIterator, parent: anytype) ?*Node {
                    if (parent.children[_self.i] != empty_node_ref)
                        return parent.children[_self.i];
                    return null;
                }
                fn body48(_self: *ChildIterator, parent: anytype) ?*Node {
                    const idx = parent.keys[_self.i];
                    if (idx != 0 and parent.children[idx - 1] != empty_node_ref)
                        return parent.children[idx - 1];
                    return null;
                }
            };
        };

        pub var empty_node: Node = .{ .empty = {} };
        pub var empty_node_ref = &empty_node;

        pub fn init(a: *std.mem.Allocator) Tree {
            return .{ .root = empty_node_ref, .size = 0, .allocator = a };
        }
        pub fn deinit(t: *Tree) void {
            t.deinitNode(t.root);
        }
        pub const Result = union(enum) { missing, found: Leaf };
        pub fn insert(t: *Tree, key: [:0]const u8, value: T) !Result {
            var _key = key;
            _key.len += 1;
            const result = try t.recursiveInsert(t.root, &t.root, _key, value, 0);
            if (result == .missing) t.size += 1;
            return result;
        }

        pub fn print(t: *Tree) !void {
            const stderr = std.io.getStdErr().outStream();
            _ = t.iter(showCb, stderr);
        }
        pub fn printToStream(t: *Tree, stream: anytype) !void {
            _ = t.iter(showCb, stream);
        }
        pub fn displayNode(stream: anytype, n: *Node, depth: usize) void {
            _ = showCb(n, stream, depth);
        }
        pub fn displayChildren(stream: anytype, n: *Node, depth: usize) void {
            var it = n.childIterator();
            while (it.next()) |child| {
                displayNode(stream, child, depth + 1);
            }
        }
        pub fn delete(t: *Tree, key: [:0]const u8) Error!Result {
            var _key = key;
            _key.len += 1;
            const result = try t.recursiveDelete(t.root, &t.root, _key, 0);
            if (result == .found) t.size -= 1;
            return result;
        }
        pub fn search(t: *Tree, key: [:0]const u8) Result {
            var _key = key;
            _key.len += 1;
            var child: **Node = &empty_node_ref;
            var _n: ?*Node = t.root;
            var prefix_len: usize = undefined;
            var depth: u32 = 0;
            while (_n) |n| {
                // Might be a leaf
                if (n.* == .leaf) {
                    // Check if the expanded path matches
                    if (std.mem.eql(u8, n.leaf.key, _key)) {
                        return Result{ .found = n.leaf };
                    }
                    return .missing;
                }
                const base = n.baseNode();

                // Bail if the prefix does not match
                if (base.partial_len > 0) {
                    prefix_len = checkPrefix(base, _key, depth);
                    if (prefix_len != math.min(MaxPrefixLen, base.partial_len))
                        return .missing;
                    depth += base.partial_len;
                }

                // Recursively search
                child = findChild(n, _key[depth]);
                _n = if (child != &empty_node_ref) child.* else null;
                depth += 1;
            }
            return .missing;
        }

        pub fn iter(t: *Tree, comptime cb: anytype, data: anytype) bool {
            return t.recursiveIter(t.root, data, 0, cb);
        }

        pub fn iterAll(t: *Tree, comptime cb: anytype, data: anytype) bool {
            return t.recursiveIterAll(t.root, data, 0, cb);
        }

        fn leafPrefixMatches(n: Leaf, prefix: []const u8) bool {
            return n.key.len > prefix.len and std.mem.startsWith(u8, n.key, prefix);
        }

        pub fn iterPrefix(t: *Tree, prefix: []const u8, cb: anytype, data: anytype) bool {
            std.debug.assert(prefix.len == 0 or prefix[prefix.len - 1] != 0);
            var child: **Node = undefined;
            var _n: ?*Node = t.root;
            var prefix_len: usize = undefined;
            var depth: u32 = 0;
            while (_n) |n| {
                // Might be a leaf
                if (n.* == .leaf) {
                    // Check if the expanded path matches
                    if (leafPrefixMatches(n.*.leaf, prefix))
                        return cb(n, data, depth);
                    return false;
                }

                // If the depth matches the prefix, we need to handle this node
                if (depth == prefix.len) {
                    if (minimum(n)) |l| {
                        if (leafPrefixMatches(l.*, prefix))
                            return t.recursiveIter(n, data, depth, cb);
                    }
                    return false;
                }

                const base = n.baseNode();

                // Bail if the prefix does not match
                if (base.partial_len > 0) {
                    prefix_len = prefixMismatch(n, prefix, depth);

                    // Guard if the mis-match is longer than the MAX_PREFIX_LEN
                    if (prefix_len > base.partial_len)
                        prefix_len = base.partial_len;

                    // If there is no match, search is terminated
                    if (prefix_len == 0) {
                        return false;
                        // If we've matched the prefix, iterate on this node
                    } else if (depth + prefix_len == prefix.len) {
                        return t.recursiveIter(n, data, depth, cb);
                    }

                    // if there is a full match, go deeper
                    depth = depth + base.partial_len;
                }

                // Recursively search
                child = findChild(n, prefix[depth]);
                _n = if (child != &empty_node_ref) child.* else null;
                depth += 1;
            }
            return false;
        }

        // Recursively destroys the tree
        fn deinitNode(t: *Tree, n: *Node) void {
            switch (n.*) {
                .empty => return,
                .leaf => {},
                .node4, .node16, .node48, .node256 => {
                    var it = n.childIterator();
                    while (it.next()) |child| {
                        t.deinitNode(child);
                    }
                },
            }
            t.deinitNodeBytes(n);
        }

        fn deinitNodeBytes(t: *Tree, n: *Node) void {
            // destroy Node + [num_keys]u8 + [num_children]*Node
            const bytes_ptr = @ptrCast([*]u8, n);
            const bytes = bytes_ptr[0 .. @sizeOf(Node) + switch (n.*) {
                .node4 => Node4.num_keys + Node4.num_children * @sizeOf(*Node),
                .node16 => Node16.num_keys + Node16.num_children * @sizeOf(*Node),
                .node48 => Node48.num_keys + Node48.num_children * @sizeOf(*Node),
                .node256 => Node256.num_keys + Node256.num_children * @sizeOf(*Node),
                .leaf => {
                    t.allocator.destroy(n);
                    return;
                },
                else => unreachable,
            }];
            t.allocator.free(bytes);
        }

        // don't allocate for the key. the client owns the keys
        fn makeLeaf(t: *Tree, key: []const u8, value: T) !*Node {
            const n = try t.allocator.create(Node);
            n.* = .{ .leaf = .{ .key = key, .value = value } };
            return n;
        }

        fn allocNode(t: *Tree, comptime Tag: std.meta.Tag(Node)) !*Node {
            const NodeT = switch (Tag) {
                .node4 => Node4,
                .node16 => Node16,
                .node48 => Node48,
                .node256 => Node256,
                else => unreachable,
            };

            // allocate enough space for a Node + [num_keys]u8 + [num_children]*Node
            var bytes = try t.allocator.alignedAlloc(u8, @alignOf(*Node), @sizeOf(Node) +
                1 * NodeT.num_keys + @sizeOf(*Node) * NodeT.num_children);
            const n = mem.bytesAsValue(Node, bytes[0..@sizeOf(Node)]);
            bytes = bytes[@sizeOf(Node)..];

            const KeysT = [NodeT.num_keys]u8;
            const keys_ptr = @ptrCast(*KeysT, bytes[0..NodeT.num_keys]);
            bytes = bytes[NodeT.num_keys..];

            const ChildrenT = [NodeT.num_children]*Node;
            const children_ptr_size = @sizeOf(*ChildrenT) * NodeT.num_children;
            const children_ptr = @ptrCast(*ChildrenT, mem.bytesAsSlice(ChildrenT, bytes[0..children_ptr_size]).ptr);

            const tagName = @tagName(Tag);
            n.* = @unionInit(Node, tagName, .{
                .num_children = 0,
                .partial_len = 0,
                .keys = keys_ptr,
                .children = children_ptr,
            });

            var node = &@field(n, tagName);
            node.keys.* = [1]u8{0} ** NodeT.num_keys;
            node.children.* = [1]*Node{&empty_node} ** NodeT.num_children;
            return n;
        }
        const Error = error{ OutOfMemory, NoMinimum };
        fn recursiveInsert(t: *Tree, n: *Node, ref: **Node, key: []const u8, value: T, depth: u32) Error!Result {
            if (n == empty_node_ref) {
                ref.* = try t.makeLeaf(key, value);
                return .missing;
            }
            if (n.* == .leaf) {
                var l = n.*.leaf;
                if (mem.eql(u8, l.key, key)) {
                    const result = Result{ .found = l };
                    n.*.leaf.value = value;
                    return result;
                }
                var new_node = try t.allocNode(.node4);
                var l2 = try t.makeLeaf(key, value);
                const longest_prefix = longestCommonPrefix(l, l2.*.leaf, depth);
                new_node.node4.partial_len = longest_prefix;
                mem.copy(u8, &new_node.node4.partial, key[depth..][0..math.min(MaxPrefixLen, longest_prefix)]);
                ref.* = new_node;
                try t.addChild4(new_node, ref, l.key[depth + longest_prefix], n);
                try t.addChild4(new_node, ref, l2.*.leaf.key[depth + longest_prefix], l2);
                return .missing;
            }
            var base = n.baseNode();
            if (base.partial_len != 0) {
                // Determine if the prefixes differ, since we need to split
                const prefix_diff = prefixMismatch(n, key, depth);
                if (prefix_diff >= base.partial_len)
                    return try t.recursiveInsertSearch(n, ref, key, value, depth + base.partial_len);

                // Create a new node
                var new_node = try t.allocNode(.node4);
                ref.* = new_node;
                new_node.node4.partial_len = prefix_diff;
                mem.copy(u8, &new_node.node4.partial, base.partial[0..math.min(MaxPrefixLen, prefix_diff)]);

                // Adjust the prefix of the old node
                if (base.partial_len <= MaxPrefixLen) {
                    try t.addChild4(new_node, ref, base.partial[prefix_diff], n);
                    base.partial_len -= (prefix_diff + 1);
                    mem.copy(u8, &base.partial, base.partial[prefix_diff + 1 ..][0..math.min(MaxPrefixLen, base.partial_len)]);
                } else {
                    base.partial_len -= (prefix_diff + 1);
                    var l = minimum(n) orelse return error.NoMinimum;
                    try t.addChild4(new_node, ref, l.key[depth + prefix_diff], n);
                    mem.copy(u8, &base.partial, l.key[depth + prefix_diff + 1 ..][0..math.min(MaxPrefixLen, base.partial_len)]);
                }

                // Insert the new leaf
                var l = try t.makeLeaf(key, value);
                try t.addChild4(new_node, ref, key[depth + prefix_diff], l);

                return .missing;
            }
            return try t.recursiveInsertSearch(n, ref, key, value, depth);
        }
        fn recursiveInsertSearch(t: *Tree, n: *Node, ref: **Node, key: []const u8, value: T, depth: u32) Error!Result {
            const child = findChild(n, key[depth]);
            if (child != &empty_node_ref) {
                return try t.recursiveInsert(child.*, child, key, value, depth + 1);
            }

            // No child, node goes within us
            var l = try t.makeLeaf(key, value);
            try t.addChild(n, ref, key[depth], l);
            return .missing;
        }
        fn longestCommonPrefix(l: Leaf, l2: Leaf, depth: usize) u8 {
            // FIXME should these be key.len - 1?
            const max_cmp = math.min(l.key.len, l2.key.len) - depth;
            var idx: u8 = 0;
            while (idx < max_cmp) : (idx += 1) {
                if (l.key[depth + idx] != l2.key[depth + idx])
                    return idx;
            }
            return idx;
        }
        fn copyHeader(dest: *BaseNode, src: *BaseNode) void {
            dest.num_children = src.num_children;
            dest.partial_len = src.partial_len;
            mem.copy(u8, &dest.partial, src.partial[0..math.min(MaxPrefixLen, src.partial_len)]);
        }

        /// Calculates the index at which the prefixes mismatch
        fn prefixMismatch(n: *Node, key: []const u8, depth: u32) u8 {
            const base = n.baseNode();
            // FIXME should this be key.len - 1?
            var max_cmp: u32 = math.min(math.min(MaxPrefixLen, base.partial_len), key.len - depth);
            var idx: u8 = 0;
            while (idx < max_cmp) : (idx += 1) {
                if (base.partial[idx] != key[depth + idx])
                    return idx;
            }
            if (base.partial_len > MaxPrefixLen) {
                const l = minimum(n);
                // FIXME should this be key.len - 1?
                max_cmp = @truncate(u32, math.min(l.?.key.len, key.len)) - depth;
                while (idx < max_cmp) : (idx += 1) {
                    if (l.?.key[idx + depth] != key[depth + idx])
                        return idx;
                }
            }
            return idx;
        }
        // Find the minimum Leaf under a node
        pub fn minimum(n: *Node) ?*Leaf {
            return switch (n.*) {
                .empty => null,
                .leaf => &n.leaf,
                .node4 => minimum(n.node4.children[0]),
                .node16 => minimum(n.node16.children[0]),
                .node48 => blk: {
                    var idx: usize = 0;
                    while (n.node48.keys[idx] == 0) : (idx += 1) {}
                    break :blk minimum(n.node48.children[n.node48.keys[idx] - 1]);
                },
                .node256 => blk: {
                    var idx: usize = 0;
                    while (n.node256.children[idx] == &empty_node) : (idx += 1) {}
                    break :blk minimum(n.node256.children[idx]);
                },
            };
        }
        pub fn maximum(n: *Node) ?*Leaf {
            // Handle base cases
            return switch (n.*) {
                .empty => null,
                .leaf => &n.leaf,
                .node4 => maximum(n.node4.children[n.node4.num_children - 1]),
                .node16 => maximum(n.node16.children[n.node16.num_children - 1]),
                .node48 => blk: {
                    var idx: u8 = 255;
                    while (n.node48.keys[idx] == 0) idx -= 1;
                    break :blk maximum(n.node48.children[n.node48.keys[idx] - 1]);
                },
                .node256 => blk: {
                    var idx: u8 = 255;
                    while (n.node256.children[idx] == &empty_node) idx -= 1;
                    break :blk maximum(n.node256.children[idx]);
                },
            };
        }

        fn findChild(n: *Node, c: u8) **Node {
            const base = n.baseNode();
            switch (n.*) {
                .node4 => {
                    var i: u8 = 0;
                    while (i < base.num_children) : (i += 1) {
                        if (n.node4.keys[i] == c) return &n.node4.children[i];
                    }
                },
                .node16 => {
                    var cmp = @splat(16, c) == @as(@Vector(16, u8), n.node16.keys.*);
                    const mask = (@as(u17, 1) << @truncate(u5, n.node16.num_children)) - 1;
                    const bitfield = @ptrCast(*u17, &cmp).* & mask;

                    if (bitfield != 0) return &n.node16.children[@ctz(usize, bitfield)];
                },
                .node48 => {
                    const i = n.node48.keys[c];
                    if (i != 0) return &n.node48.children[i - 1];
                },
                .node256 => {
                    // seems like it shouldn't be, but this check is necessary
                    // removing it makes many things fail spectularly and mysteriously
                    // i thought removing this check would be ok as all children are initialized to empty_node_ref
                    // but that is NOT the case...
                    // the reason its necessary is that the address of the child is _NOT_ equal to the
                    // address of empty_node_ref. of course it isnt.
                    // if (n.node256.children[c] != empty_node_ref)
                    if (n.node256.children[c] != empty_node_ref) return &n.node256.children[c];
                },
                .leaf, .empty => unreachable,
            }
            return &empty_node_ref;
        }

        fn addChild(t: *Tree, n: *Node, ref: **Node, c: u8, child: *Node) Error!void {
            switch (n.*) {
                .node4 => try t.addChild4(n, ref, c, child),
                .node16 => try t.addChild16(n, ref, c, child),
                .node48 => try t.addChild48(n, ref, c, child),
                .node256 => try t.addChild256(n, ref, c, child),
                .leaf, .empty => unreachable,
            }
        }

        fn addChild4(t: *Tree, n: *Node, ref: **Node, c: u8, child: *Node) !void {
            if (n.node4.num_children < 4) {
                var idx: usize = 0;
                while (idx < n.node4.num_children) : (idx += 1) {
                    if (c < n.node4.keys[idx]) break;
                }
                const shift_len = n.node4.num_children - idx;
                mem.copyBackwards(u8, n.node4.keys[idx + 1 ..], n.node4.keys[idx..][0..shift_len]);
                mem.copyBackwards(*Node, n.node4.children[idx + 1 ..], n.node4.children[idx..][0..shift_len]);
                n.node4.keys[idx] = c;
                n.node4.children[idx] = child;
                n.node4.num_children += 1;
            } else {
                var new_node = try t.allocNode(.node16);
                mem.copy(*Node, new_node.node16.children, n.node4.children);
                mem.copy(u8, new_node.node16.keys, n.node4.keys);
                copyHeader(new_node.node16.baseNode(), n.node4.baseNode());
                ref.* = new_node;
                t.deinitNodeBytes(n);
                try t.addChild16(new_node, ref, c, child);
            }
        }

        fn addChild16(t: *Tree, n: *Node, ref: **Node, c: u8, child: anytype) Error!void {
            if (n.node16.num_children < 16) {
                var cmp = @splat(16, c) < @as(@Vector(16, u8), n.node16.keys.*);
                const mask = (@as(u17, 1) << @truncate(u5, n.node16.num_children)) - 1;
                const bitfield = @ptrCast(*u17, &cmp).* & mask;

                var idx: usize = 0;
                if (bitfield != 0) {
                    idx = @ctz(usize, bitfield);
                    const shift_len = n.node16.num_children - idx;
                    mem.copyBackwards(u8, n.node16.keys[idx + 1 ..], n.node16.keys[idx..][0..shift_len]);
                    mem.copyBackwards(*Node, n.node16.children[idx + 1 ..], n.node16.children[idx..][0..shift_len]);
                } else idx = n.node16.num_children;

                n.node16.keys[idx] = c;
                n.node16.children[idx] = child;
                n.node16.num_children += 1;
            } else {
                var new_node = try t.allocNode(.node48);
                mem.copy(*Node, new_node.node48.children, n.node16.children);
                const base = n.baseNode();
                var i: u8 = 0;
                while (i < base.num_children) : (i += 1)
                    new_node.node48.keys[n.node16.keys[i]] = i + 1;
                copyHeader(new_node.baseNode(), base);
                ref.* = new_node;
                t.deinitNodeBytes(n);
                try t.addChild48(new_node, ref, c, child);
            }
        }

        fn addChild48(t: *Tree, n: *Node, ref: **Node, c: u8, child: anytype) Error!void {
            if (n.node48.num_children < 48) {
                var pos: u8 = 0;
                while (n.node48.children[pos] != &empty_node) : (pos += 1) {}
                n.node48.children[pos] = child;
                n.node48.keys[c] = pos + 1;
                n.node48.num_children += 1;
            } else {
                var new_node = try t.allocNode(.node256);
                var i: usize = 0;
                const old_children = n.node48.children;
                const old_keys = n.node48.keys;
                while (i < 256) : (i += 1) {
                    if (old_keys[i] != 0)
                        new_node.node256.children[i] = old_children[old_keys[i] - 1];
                }
                copyHeader(new_node.baseNode(), n.baseNode());
                ref.* = new_node;
                t.deinitNodeBytes(n);
                try t.addChild256(new_node, ref, c, child);
            }
        }

        fn addChild256(t: *Tree, n: *Node, ref: **Node, c: u8, child: anytype) Error!void {
            _ = t;
            _ = ref;
            n.node256.num_children += 1;
            n.node256.children[c] = child;
        }

        fn checkPrefix(n: *BaseNode, key: []const u8, depth: usize) usize {
            // FIXME should this be key.len - 1?
            const max_cmp = math.min(math.min(n.partial_len, MaxPrefixLen), key.len - depth);
            var idx: usize = 0;
            while (idx < max_cmp) : (idx += 1) {
                if (n.partial[idx] != key[depth + idx])
                    return idx;
            }
            return idx;
        }

        /// calls cb in order on leaf nodes until cb returns true
        fn recursiveIter(t: *Tree, n: *Node, data: anytype, depth: usize, cb: anytype) bool {
            switch (n.*) {
                .empty => {},
                .leaf => return cb(n, data, depth),
                .node4, .node16, .node48, .node256 => {
                    var ci = n.childIterator();
                    while (ci.next()) |child| {
                        if (t.recursiveIter(child, data, depth + 1, cb))
                            return true;
                    }
                },
            }
            return false;
        }

        /// calls cb in order on all nodes (not just leaves) until cb returns true
        fn recursiveIterAll(t: *Tree, n: *Node, data: anytype, depth: usize, cb: anytype) bool {
            switch (n.*) {
                .empty => {},
                .leaf => return cb(n, data, depth),
                .node4, .node16, .node48, .node256 => {
                    if (cb(n, data, depth)) return true;
                    var ci = n.childIterator();
                    while (ci.next()) |child| {
                        if (t.recursiveIterAll(child, data, depth + 1, cb))
                            return true;
                    }
                },
            }
            return false;
        }

        const spaces = [1]u8{' '} ** 256;
        pub fn showCb(n: *Node, data: anytype, depth: usize) bool {
            const streamPrint = struct {
                fn _(stream: anytype, comptime fmt: []const u8, args: anytype) void {
                    _ = stream.print(fmt, args) catch unreachable;
                }
            }._;

            switch (n.*) {
                .empty => streamPrint(data, "empty\n", .{}),
                .leaf => streamPrint(data, "{s}-> {s} = {}\n", .{ spaces[0 .. depth * 2], n.leaf.key, n.leaf.value }),
                .node4 => streamPrint(data, "{s}4   [{s}] ({s}) {} children\n", .{
                    spaces[0 .. depth * 2],
                    &n.node4.keys.*,
                    n.node4.partial[0..math.min(MaxPrefixLen, n.node4.partial_len)],
                    n.node4.num_children,
                }),
                .node16 => streamPrint(data, "{s}16  [{s}] ({s}) {} children\n", .{
                    spaces[0 .. depth * 2],
                    n.node16.keys.*,
                    n.node16.partial[0..math.min(MaxPrefixLen, n.node16.partial_len)],
                    n.node16.num_children,
                }),
                .node48 => |nn| {
                    streamPrint(data, "{s}48  [", .{spaces[0 .. depth * 2]});
                    for (nn.keys) |c, i| {
                        if (c != 0)
                            streamPrint(data, "{c}", .{@truncate(u8, i)});
                    }
                    streamPrint(data, "] ({s}) {} children\n", .{ nn.partial, n.node48.num_children });
                },
                .node256 => |nn| {
                    streamPrint(data, "{s}256 [", .{spaces[0 .. depth * 2]});
                    for (nn.children) |child, i| {
                        if (child != &empty_node)
                            streamPrint(data, "{c}", .{@truncate(u8, i)});
                    }
                    streamPrint(data, "] ({s}) {} children\n", .{ nn.partial, n.node256.num_children });
                },
            }
            return false;
        }

        fn recursiveDelete(t: *Tree, n: *Node, ref: **Node, key: []const u8, _depth: usize) Error!Result {
            var depth = _depth;
            if (n == empty_node_ref) return .missing;
            if (n.* == .leaf) {
                const l = n.*.leaf;
                if (mem.eql(u8, n.*.leaf.key, key)) {
                    const result = Result{ .found = l };
                    t.deinitNode(n);
                    ref.* = empty_node_ref;
                    return result;
                }
                return .missing;
            }
            const base = n.baseNode();
            if (base.partial_len > 0) {
                const prefix_len = checkPrefix(base, key, depth);
                if (prefix_len != math.min(MaxPrefixLen, base.partial_len))
                    return .missing;
                depth += base.partial_len;
            }

            const child = findChild(n, key[depth]);
            if (child == &empty_node_ref) return .missing;
            const childp = child.*;
            if (childp.* == .leaf) {
                const l = childp.*.leaf;
                if (mem.eql(u8, l.key, key)) {
                    try t.removeChild(n, ref, key[depth], child);
                    return Result{ .found = l };
                }
                return .missing;
            } else return try t.recursiveDelete(child.*, child, key, depth + 1);
        }
        fn removeChild(t: *Tree, n: *Node, ref: **Node, c: u8, l: **Node) !void {
            switch (n.*) {
                .node4 => return t.removeChild4(n, ref, l),
                .node16 => return try t.removeChild16(n, ref, l),
                .node48 => return try t.removeChild48(n, ref, c),
                .node256 => return try t.removeChild256(n, ref, c),
                .leaf, .empty => unreachable,
            }
        }
        fn removeChild4(t: *Tree, n: *Node, ref: **Node, l: **Node) void {
            const pos = (@ptrToInt(l) - @ptrToInt(&n.node4.children.*)) / 8;
            if (!(0 <= pos and pos < 4)) warn("bad pos {}\n", .{pos});
            std.debug.assert(0 <= pos and pos < 4);
            t.deinitNode(n.node4.children[pos]);
            const base = n.baseNode();
            mem.copy(u8, n.node4.keys[pos..], n.node4.keys[pos + 1 ..]);
            mem.copy(*Node, n.node4.children[pos..], n.node4.children[pos + 1 ..]);
            base.num_children -= 1;
            n.node4.keys[base.num_children] = 0;
            n.node4.children[base.num_children] = empty_node_ref;
            // Remove nodes with only a single child
            if (base.num_children == 1) {
                const child = n.node4.children[0];
                if (child.* != .leaf) {
                    // Concatenate the prefixes
                    var prefix = base.partial_len;
                    if (prefix < MaxPrefixLen) {
                        base.partial[prefix] = n.node4.keys[0];
                        prefix += 1;
                    }
                    const child_base = child.baseNode();
                    if (prefix < MaxPrefixLen) {
                        const sub_prefix = math.min(child_base.partial_len, MaxPrefixLen - prefix);
                        mem.copy(u8, base.partial[prefix..], child_base.partial[0..sub_prefix]);
                        prefix += sub_prefix;
                    }
                    mem.copy(u8, &child_base.partial, base.partial[0..math.min(prefix, MaxPrefixLen)]);
                    child_base.partial_len += base.partial_len + 1;
                }
                ref.* = child;
                t.deinitNodeBytes(n);
            }
        }
        fn removeChild16(t: *Tree, n: *Node, ref: **Node, l: **Node) Error!void {
            const pos = (@ptrToInt(l) - @ptrToInt(&n.node16.children.*)) / 8;
            std.debug.assert(0 <= pos and pos < 16);
            t.deinitNode(n.node16.children[pos]);
            const base = n.baseNode();
            mem.copy(u8, n.node16.keys[pos..], n.node16.keys[pos + 1 ..]);
            mem.copy(*Node, n.node16.children[pos..], n.node16.children[pos + 1 ..]);
            base.num_children -= 1;
            n.node16.keys[base.num_children] = 0;
            n.node16.children[base.num_children] = empty_node_ref;
            if (base.num_children == 3) {
                const new_node = try t.allocNode(.node4);
                ref.* = new_node;
                copyHeader(new_node.baseNode(), base);
                mem.copy(u8, new_node.node4.keys, n.node16.keys[0..3]);
                mem.copy(*Node, new_node.node4.children, n.node16.children[0..3]);
                t.deinitNodeBytes(n);
            }
        }
        fn removeChild48(t: *Tree, n: *Node, ref: **Node, c: u8) Error!void {
            const base = n.baseNode();
            var pos = n.node48.keys[c];
            n.node48.keys[c] = 0;
            t.deinitNode(n.node48.children[pos - 1]);
            n.node48.children[pos - 1] = empty_node_ref;
            base.num_children -= 1;

            if (base.num_children == 12) {
                const new_node = try t.allocNode(.node16);
                ref.* = new_node;
                copyHeader(new_node.baseNode(), base);

                var childi: u8 = 0;
                var i: u8 = 0;
                while (true) : (i += 1) {
                    pos = n.node48.keys[i];
                    if (pos != 0) {
                        new_node.node16.keys[childi] = i;
                        new_node.node16.children[childi] = n.node48.children[pos - 1];
                        childi += 1;
                    }
                    if (i == 255) break;
                }
                t.deinitNodeBytes(n);
            }
        }
        fn removeChild256(t: *Tree, n: *Node, ref: **Node, c: u8) Error!void {
            const base = n.baseNode();
            t.deinitNode(n.node256.children[c]);
            n.node256.children[c] = empty_node_ref;
            base.num_children -= 1;

            // Resize to a node48 on underflow, not immediately to prevent
            // trashing if we sit on the 48/49 boundary
            if (base.num_children == 37) {
                const new_node = try t.allocNode(.node48);
                ref.* = new_node;
                copyHeader(new_node.baseNode(), base);

                var pos: u8 = 0;
                var i: u8 = 0;
                while (true) : (i += 1) {
                    if (n.node256.children[i] != empty_node_ref) {
                        new_node.node48.children[pos] = n.node256.children[i];
                        new_node.node48.keys[i] = pos + 1;
                        pos += 1;
                    }
                    if (i == 255) break;
                }
                t.deinitNodeBytes(n);
            }
        }
    };
}
