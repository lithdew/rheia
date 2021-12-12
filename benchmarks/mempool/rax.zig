const std = @import("std");

const mem = std.mem;
const sort = std.sort;
const math = std.math;
const heap = std.heap;
const testing = std.testing;

const assert = std.debug.assert;

comptime {
    assert(@sizeOf(Node) == @sizeOf(u32));
}

pub const Data = *c_void;

/// (| Header (32-bit) | Data ([*]u8) | Data Padding ([*]u8) |) Compressed/Uncompressed Children (*Node or [*]*Node) | Key (Data) Pointer If Not Null ([*]const u8)
///
/// A Node is aligned to the size of a pointer.
pub const Node = packed struct {
    pub const max_size = (1 << 29) - 1;

    is_key: bool = false,
    is_null: bool = false,
    is_compressed: bool = false,
    size: u29,

    pub fn init(gpa: mem.Allocator, num_children: u29, holds_data: bool) !*Node {
        var size: usize = mem.alignForward(@sizeOf(Node) + num_children, @alignOf(*c_void)) + @sizeOf(*Node) * num_children;
        if (holds_data) size += @sizeOf(Data);

        const node = @ptrCast(*Node, (try gpa.alloc(u8, size)).ptr);
        node.* = .{ .size = num_children };
        return node;
    }

    pub fn initCompressed(gpa: mem.Allocator, num_children: u29, holds_data: bool) !*Node {
        var size: usize = mem.alignForward(@sizeOf(Node) + num_children, @alignOf(*c_void)) + @sizeOf(*Node);
        if (holds_data) size += @sizeOf(Data);

        const node = @ptrCast(*Node, (try gpa.alloc(u8, size)).ptr);
        node.* = .{ .size = num_children, .is_compressed = num_children > 1 };
        return node;
    }

    pub fn deinit(self: *Node, gpa: mem.Allocator) void {
        gpa.free(@ptrCast([*]u8, self)[0..self.length()]);
    }

    pub fn deallocate(self: *Node, gpa: mem.Allocator) void {
        for (self.children()) |child| {
            child.deallocate(gpa);
        }
        self.deinit(gpa);
    }

    pub fn reallocForData(self: *Node, gpa: mem.Allocator, value: ?Data) !*Node {
        if (value == null) return self;

        assert(!self.is_key or self.is_null);

        const len = self.length();
        const bytes = try gpa.realloc(@ptrCast([*]u8, self)[0..len], len + @sizeOf(Data));

        return @ptrCast(*Node, bytes);
    }

    pub fn addChild(self: *Node, gpa: mem.Allocator, character: u8, child: **Node, parent_link: ***Node) !*Node {
        assert(!self.is_compressed);

        const current_len = self.length();
        self.size += 1;
        const new_len = self.length();
        self.size -= 1;

        child.* = try Node.init(gpa, 0, false);
        errdefer child.*.deinit(gpa);

        const new_node = @ptrCast(*Node, try gpa.realloc(@ptrCast([*]u8, self)[0..current_len], new_len));
        errdefer new_node.deinit(gpa);

        // move data ptr if not null

        if (new_node.is_key and !new_node.is_null) {
            const src = @intToPtr(*Data, @ptrToInt(new_node) + current_len - @sizeOf(Data));
            const dst = @intToPtr(*Data, @ptrToInt(new_node) + new_len - @sizeOf(Data));
            dst.* = src.*;
        }

        // find pos where 'character' can be inserted while guaranteeing that the nodes' path
        // remains sorted

        const pos: usize = for (new_node.path()) |char, pos| {
            if (char > character) break pos;
        } else new_node.size;

        // move children ptrs to make room for 'character' (copy starting from the back)
        // (essentially insertion sort)

        const node_children = new_node.children();
        const shift = new_len - current_len - @sizeOf(Data);
        const shifted_children = @intToPtr([*]*Node, @ptrToInt(node_children.ptr) + shift)[0 .. node_children.len + 1];

        mem.copyBackwards(*Node, shifted_children[pos..][1..], node_children[pos..]);
        if (shift != 0) mem.copyBackwards(*Node, shifted_children[0..pos], node_children[0..pos]);

        // make room for 'character' in the node path section
        // (essentially insertion sort)

        const node_path = new_node.path();
        const shifted_path = node_path.ptr[0 .. node_path.len + 1];

        mem.copyBackwards(u8, shifted_path[pos + 1 ..], node_path[pos..]);
        shifted_path[pos] = character;

        // link 'character' child node to parent and increment children count by 1

        new_node.size += 1;

        const child_field = &new_node.children()[pos];
        child_field.* = child.*;
        parent_link.* = child_field;

        return new_node;
    }

    pub fn removeChild(self: *Node, gpa: mem.Allocator, child: *Node) *Node {
        if (self.is_compressed) {
            const parent_data = if (self.is_key and !self.is_null) self.data().* else null;

            self.is_compressed = false;
            self.is_null = false;
            self.size = 0;

            if (self.is_key) {
                if (parent_data) |d| {
                    self.data().* = d;
                } else {
                    self.is_null = true;
                }
            }

            return self;
        }

        // remove child's character from parent's path

        const parent_children = self.children();
        const child_index = mem.indexOfScalar(*Node, parent_children, child) orelse unreachable;

        const tail_len = self.size - child_index - 1;
        mem.copy(u8, self.path()[child_index..][0..tail_len], self.path()[child_index + 1 ..][0..tail_len]);

        // remove child ptr from parent's children

        // const shift: usize = if (mem.alignBackward(@sizeOf(Node) + self.size, @alignOf(*c_void)) == @sizeOf(Node) + self.size + 1) 1 else 0;
        const shift: usize = if ((self.size + 4) % @sizeOf(*c_void) == 1) 1 else 0;
        if (shift != 0) {
            mem.copy(*Node, (parent_children.ptr - shift)[0 .. self.size - tail_len - 1], parent_children[0 .. self.size - tail_len - 1]);
        }

        const value_len: usize = if (self.is_key and !self.is_null) 1 else 0; // value_len should (ideally) be @sizeOf(Data) to handle variable lengths
        mem.copy(*Node, (parent_children.ptr + child_index - shift)[0 .. tail_len + value_len], (parent_children.ptr + child_index + 1)[0 .. tail_len + value_len]);

        const current_len = self.length();
        self.size -= 1;

        return @ptrCast(*Node, (gpa.realloc(@ptrCast([*]u8, self)[0..current_len], self.length()) catch return self).ptr);
    }

    pub fn findParentLink(self: *Node, child: *Node) **Node {
        const child_index = mem.indexOfScalar(*Node, self.children(), child) orelse unreachable;
        return &self.children()[child_index];
    }

    pub fn compress(self: *Node, gpa: mem.Allocator, node_path: []const u8, child: **Node) !*Node {
        assert(self.size == 0 and !self.is_compressed);

        child.* = try Node.init(gpa, 0, false);
        errdefer child.*.deinit(gpa);

        var new_size = mem.alignForward(@sizeOf(Node) + node_path.len, @alignOf(*c_void)) + @sizeOf(*Node);
        var maybe_data: ?Data = if (self.is_key and !self.is_null) self.data().* else null;
        if (maybe_data != null) new_size += @sizeOf(Data);

        const new_node = @ptrCast(*Node, try gpa.realloc(@ptrCast([*]u8, self)[0..self.length()], new_size));
        errdefer new_node.deinit(gpa);

        new_node.is_compressed = true;
        new_node.size = @intCast(u29, node_path.len);
        mem.copy(u8, new_node.path(), node_path);

        if (new_node.is_key) {
            if (maybe_data) |node_data| {
                new_node.data().* = node_data;
            }
        }

        new_node.lastChild()[0] = child.*;

        return new_node;
    }

    pub fn data(self: *Node) *Data {
        return @intToPtr(*Data, @ptrToInt(self) + self.length() - @sizeOf(Data));
    }

    pub fn path(self: *Node) []u8 {
        return @intToPtr([*]u8, @ptrToInt(self) + @sizeOf(Node))[0..self.size];
    }

    pub fn children(self: *Node) []*Node {
        return self.firstChild()[0..if (self.is_compressed) 1 else self.size];
    }

    pub fn firstChild(self: *Node) [*]*Node {
        return @intToPtr([*]*Node, mem.alignForward(@ptrToInt(self) + @sizeOf(Node) + self.size, @alignOf(*c_void)));
    }

    pub fn lastChild(self: *Node) [*]*Node {
        var address = @ptrToInt(self) + self.length();
        if (self.is_key and !self.is_null) {
            address -= @sizeOf(Data);
        }
        address -= @sizeOf(*Node);
        return @intToPtr([*]*Node, address);
    }

    pub fn length(self: *Node) usize {
        var result = mem.alignForward(@sizeOf(Node) + self.size, @alignOf(*c_void));
        if (self.is_compressed) {
            result += @sizeOf(*Node);
        } else {
            result += @sizeOf(*Node) * self.size;
        }
        if (self.is_key and !self.is_null) {
            result += @sizeOf(Data);
        }
        return result;
    }
};

pub const Trie = struct {
    head: *Node,
    num_nodes: usize = 1,
    num_elements: usize = 0,

    pub fn init(gpa: mem.Allocator) !Trie {
        const head = try Node.init(gpa, 0, false);
        return Trie{ .head = head };
    }

    pub fn deinit(self: *Trie, gpa: mem.Allocator) void {
        self.deallocate(gpa, self.head);
        assert(self.num_nodes == 0);
    }

    pub fn deallocate(self: *Trie, gpa: mem.Allocator, node: *Node) void {
        for (node.children()) |child| {
            self.deallocate(gpa, child);
        }
        node.deinit(gpa);
        self.num_nodes -= 1;
    }

    pub fn first(self: *Trie, key: *std.ArrayList(u8)) !?Data {
        key.clearRetainingCapacity();

        var head = self.head;
        while (head.size != 0) : (head = head.firstChild()[0]) {
            if (head.is_compressed) {
                try key.appendSlice(head.path());
            } else {
                try key.append(head.path()[0]);
            }
        }

        if (head.is_key and !head.is_null) {
            return head.data().*;
        }
        return null;
    }

    pub fn last(self: *Trie, key: *std.ArrayList(u8)) !?Data {
        key.clearRetainingCapacity();

        var head = self.head;
        while (head.size != 0) : (head = head.lastChild()[0]) {
            if (head.is_compressed) {
                try key.appendSlice(head.path());
            } else {
                try key.append(head.path()[0]);
            }
        }

        if (head.is_key and !head.is_null) {
            return head.data().*;
        }
        return null;
    }

    pub fn find(self: *Trie, key: []const u8) ?Data {
        var stop_node: *Node = undefined;
        var split_pos: usize = 0;

        const index = self.walk(key, .{ .stop_node = &stop_node, .split_pos = &split_pos }) catch unreachable;
        if (index != key.len or (stop_node.is_compressed and split_pos != 0) or !stop_node.is_key) {
            return null;
        }
        return if (stop_node.is_null) null else stop_node.data().*;
    }

    pub const WalkParams = struct {
        stop_node: ?**Node = null,
        parent_link_node: ?***Node = null,
        split_pos: ?*usize = null,
        stack: ?*Stack = null,
    };

    pub fn walk(self: *Trie, key: []const u8, params: WalkParams) !usize {
        var parent_link = &self.head;
        var head = self.head;

        var i: usize = 0;
        var j: usize = 0;
        while (head.size != 0 and i < key.len) {
            const path = head.path();

            if (head.is_compressed) {
                if (mem.indexOfDiff(u8, path, key[i..][0..math.min(key[i..].len, path.len)])) |diff_index| {
                    i += diff_index;
                    j = diff_index;
                    break;
                }
                i += path.len;
            } else {
                j = mem.indexOfScalar(u8, path, key[i]) orelse {
                    j = path.len;
                    break;
                };
                i += 1;
            }

            if (params.stack) |stack_ptr| {
                try stack_ptr.push(head);
            }

            parent_link = &head.children()[j];
            head = parent_link.*;
            j = 0;
        }

        if (params.stop_node) |stop_node_ptr| {
            stop_node_ptr.* = head;
        }

        if (params.parent_link_node) |parent_link_node_ptr| {
            parent_link_node_ptr.* = parent_link;
        }

        if (params.split_pos) |split_pos_ptr| {
            if (head.is_compressed) {
                split_pos_ptr.* = j;
            }
        }

        return i;
    }

    pub const InsertParams = struct {
        old: ?*?Data = null,
        overwrite: bool = false,
    };

    pub fn insert(self: *Trie, gpa: mem.Allocator, key: []const u8, value: ?Data, params: InsertParams) !bool {
        var head: *Node = undefined;
        var parent_link: **Node = undefined;
        var j: usize = 0;
        var i: usize = self.walk(key, .{ .stop_node = &head, .parent_link_node = &parent_link, .split_pos = &j }) catch unreachable;

        // case 0: matching node found, optionally overwrite data

        if (i == key.len and (!head.is_compressed or j == 0)) {
            if (!head.is_key or (head.is_null and params.overwrite)) {
                head = try head.reallocForData(gpa, value);
                parent_link.* = head;
            }

            if (head.is_key) {
                if (params.old) |old_ptr| {
                    old_ptr.* = if (head.is_null) null else head.data().*;
                }

                if (params.overwrite) {
                    if (value) |v| {
                        head.is_null = false;
                        head.data().* = v;
                    } else {
                        head.is_null = true;
                    }
                }
                return false;
            }

            head.is_key = true;
            if (value) |v| {
                head.is_null = false;
                head.data().* = v;
            } else {
                head.is_null = true;
            }
            self.num_elements += 1;
            return true;
        }

        // case 1: stopped in the middle of compressed node, split three-way into a compressed
        // prefix node, split node, and a compressed postfix node

        // prefix_node                                <-- 'value' set here
        //            |_
        //               split_node                   <-- 'head' set here
        //                         |_
        //                            postfix_node    <-- children links of old 'head' moved here
        //                                         |_

        if (head.is_compressed and i != key.len) {
            const next = head.lastChild()[0];

            const prefix_len = j;
            const postfix_len = head.size - j - 1;

            const split_node_is_key = prefix_len == 0 and (head.is_key and !head.is_null);

            const split_node = try Node.init(gpa, 1, split_node_is_key);
            errdefer split_node.deinit(gpa);

            var prefix_node_ptr: ?*Node = null;
            errdefer if (prefix_node_ptr) |prefix_node| prefix_node.deinit(gpa);

            var postfix_node_ptr: ?*Node = null;
            errdefer if (postfix_node_ptr) |postfix_node| postfix_node.deinit(gpa);

            if (prefix_len != 0) {
                prefix_node_ptr = try Node.initCompressed(gpa, @intCast(u29, prefix_len), head.is_key and !head.is_null);
            }

            if (postfix_len != 0) {
                postfix_node_ptr = try Node.initCompressed(gpa, @intCast(u29, postfix_len), false);
            }

            split_node.path()[0] = head.path()[prefix_len];

            if (prefix_len == 0) {
                // 3a: replace old node with split node
                if (head.is_key) {
                    split_node.is_key = true;
                    if (!head.is_null) {
                        split_node.is_null = false;
                        split_node.data().* = head.data().*;
                    } else {
                        split_node.is_null = true;
                    }
                }
                parent_link.* = split_node;
            } else {
                // 3b: trim compressed node into prefix node
                const prefix_node = prefix_node_ptr.?;

                mem.copy(u8, prefix_node.path()[0..prefix_len], head.path()[0..prefix_len]);
                if (head.is_key and !head.is_null) {
                    prefix_node.is_key = true;
                    prefix_node.data().* = head.data().*;
                }

                prefix_node.lastChild()[0] = split_node;
                parent_link.* = prefix_node;
                parent_link = &prefix_node.lastChild()[0];

                self.num_nodes += 1;
            }

            if (postfix_len == 0) {
                // 4b: use next as postfix node
                postfix_node_ptr = next;
            } else {
                // 4a: create a postfix node
                const postfix_node = postfix_node_ptr.?;

                mem.copy(u8, postfix_node.path()[0..postfix_len], head.path()[prefix_len + 1 ..][0..postfix_len]);
                postfix_node.lastChild()[0] = next;

                self.num_nodes += 1;
            }

            split_node.lastChild()[0] = postfix_node_ptr.?;

            head.deinit(gpa);
            head = split_node;
        } else if (head.is_compressed and i == key.len) {
            const prefix_len = j;
            const postfix_len = head.size - j;

            const prefix_node = try Node.initCompressed(gpa, @intCast(u29, prefix_len), head.is_key and !head.is_null);
            errdefer prefix_node.deinit(gpa);

            const postfix_node = try Node.initCompressed(gpa, @intCast(u29, postfix_len), value != null);
            errdefer postfix_node.deinit(gpa);

            const next = head.lastChild()[0];

            // create prefix node

            if (head.is_key) {
                prefix_node.is_key = true;
                if (!head.is_null) {
                    prefix_node.is_null = false;
                    prefix_node.data().* = head.data().*;
                } else {
                    prefix_node.is_null = true;
                }
            }
            mem.copy(u8, prefix_node.path()[0..prefix_len], head.path()[0..prefix_len]);
            parent_link.* = prefix_node;
            prefix_node.lastChild()[0] = postfix_node;

            // create postfix node

            postfix_node.is_key = true;
            if (value) |v| {
                postfix_node.is_null = false;
                postfix_node.data().* = v;
            } else {
                postfix_node.is_null = true;
            }
            mem.copy(u8, postfix_node.path()[0..postfix_len], head.path()[j..][0..postfix_len]);
            postfix_node.lastChild()[0] = next;
            self.num_nodes += 1;

            // done!

            self.num_elements += 1;
            head.deinit(gpa);
            return true;
        }

        errdefer if (head.size == 0) {
            head.is_null = true;
            head.is_key = true;
            self.num_elements += 1;

            assert(self.remove(gpa, key[0..i], null) catch true);
        };

        while (i < key.len) {
            var child: *Node = undefined;
            if (head.size == 0 and key.len - i > 0) {
                const compressed_size = math.min(Node.max_size, key.len - i);
                head = try head.compress(gpa, key[i..][0..compressed_size], &child);
                parent_link.* = head;
                parent_link = &head.lastChild()[0];
                i += compressed_size;
            } else {
                var new_parent_link: **Node = undefined;
                head = try head.addChild(gpa, key[i], &child, &new_parent_link);
                parent_link.* = head;
                parent_link = new_parent_link;
                i += 1;
            }
            self.num_nodes += 1;
            head = child;
        }

        head = try head.reallocForData(gpa, value);
        if (!head.is_key) self.num_elements += 1;

        head.is_key = true;
        if (value) |v| {
            head.is_null = false;
            head.data().* = v;
        } else {
            head.is_null = true;
        }

        parent_link.* = head;

        return true;
    }

    pub fn remove(self: *Trie, gpa: mem.Allocator, key: []const u8, old: ?*?Data) !bool {
        var stack = Stack.init(gpa);
        defer stack.deinit();

        var head: *Node = undefined;
        var split_pos: usize = 0;

        const i = try self.walk(key, .{ .stop_node = &head, .split_pos = &split_pos, .stack = &stack });
        if (i != key.len or (head.is_compressed and split_pos != 0) or !head.is_key) {
            return false;
        }

        if (old) |old_ptr| {
            old_ptr.* = head.data().*;
        }

        head.is_key = false;
        self.num_elements -= 1;

        var try_compress = false;

        if (head.size == 0) {
            var child_ptr: ?*Node = null;
            while (head != self.head) {
                child_ptr = head;
                child_ptr.?.deinit(gpa);
                self.num_nodes -= 1;

                head = stack.pop().?;
                if (head.is_key or (!head.is_compressed and head.size != 1)) {
                    break;
                }
            }

            if (child_ptr) |child| {
                const new = head.removeChild(gpa, child);
                if (new != head) {
                    const parent_ptr = stack.peek();
                    const parent_link = if (parent_ptr) |parent| parent.findParentLink(head) else &self.head;
                    parent_link.* = new;
                }

                if (new.size == 1 and !new.is_key) {
                    try_compress = true;
                    head = new;
                }
            }
        } else if (head.size == 1) {
            try_compress = true;
        }

        if (try_compress) {
            var parent_ptr: ?*Node = null;
            while (true) {
                parent_ptr = stack.pop();
                if (parent_ptr) |parent| {
                    if (parent.is_key or (!parent.is_compressed and parent.size != 1)) {
                        break;
                    }
                    head = parent;
                } else {
                    break;
                }
            }

            // see if there's any nodes that can be compressed down

            var start = head;
            var compressed_size = head.size;
            var nodes: usize = 1;

            while (head.size != 0) {
                head = head.lastChild()[0];
                if (head.is_key or (!head.is_compressed and head.size != 1)) {
                    break;
                }

                if (compressed_size + head.size > Node.max_size) {
                    break;
                }

                nodes += 1;
                compressed_size += head.size;
            }

            if (nodes > 1) {
                const new = try Node.initCompressed(gpa, compressed_size, false);
                errdefer new.deinit(gpa);

                self.num_nodes += 1;

                compressed_size = 0;
                head = start;

                while (head.size != 0) {
                    mem.copy(u8, new.path()[compressed_size..], head.path());
                    compressed_size += head.size;

                    var to_free = head;
                    head = head.lastChild()[0];

                    to_free.deinit(gpa);
                    self.num_nodes -= 1;

                    if (head.is_key or (!head.is_compressed and head.size != 1)) {
                        break;
                    }
                }

                new.lastChild()[0] = head;

                if (parent_ptr) |parent| {
                    parent.findParentLink(start).* = new;
                } else {
                    self.head = new;
                }
            }
        }

        return true;
    }
};

pub const Stack = struct {
    // sfa: heap.StackFallbackAllocator(32),
    gpa: mem.Allocator,
    entries: std.ArrayListUnmanaged(*Node) = .{},

    pub fn init(gpa: mem.Allocator) Stack {
        // return Stack{ .sfa = heap.stackFallback(32, gpa) };
        return Stack{ .gpa = gpa };
    }

    pub fn deinit(self: *Stack) void {
        // self.entries.deinit(&self.sfa.allocator);
        self.entries.deinit(self.gpa);
    }

    pub fn push(self: *Stack, entry: *Node) !void {
        // return self.entries.append(&self.sfa.allocator, entry);
        return self.entries.append(self.gpa, entry);
    }

    pub fn pop(self: *Stack) ?*Node {
        return self.entries.popOrNull();
    }

    pub fn peek(self: *Stack) ?*Node {
        return if (self.entries.items.len == 0) null else self.entries.items[self.entries.items.len - 1];
    }
};

test {
    testing.refAllDecls(@This());
}

test "create node" {
    const node = try Node.init(testing.allocator, 12, true);
    defer node.deinit(testing.allocator);
}

test "create trie" {
    var trie = try Trie.init(testing.allocator);
    defer trie.deinit(testing.allocator);
}

test "add child" {
    var child: *Node = undefined;
    var parent: **Node = undefined;

    inline for (.{ "bac", "abc", "cba", "abcekfdl", "lfkgdr" }) |text| {
        var node = try Node.init(testing.allocator, 0, false);
        defer node.deallocate(testing.allocator);

        inline for (text) |character| {
            node = try node.addChild(testing.allocator, character, &child, &parent);
        }

        try testing.expectEqual(@intCast(u29, text.len), node.size);

        var sorted: [text.len]u8 = undefined;
        mem.copy(u8, &sorted, text);
        sort.sort(u8, &sorted, {}, comptime sort.asc(u8));

        try testing.expectEqualStrings(&sorted, node.path());
        try testing.expectEqualSlices(*Node, node.firstChild()[0..text.len], (node.lastChild() - text.len + 1)[0..text.len]);
    }
}

test "compress node" {
    var node = try Node.init(testing.allocator, 0, false);
    defer node.deinit(testing.allocator);

    var child: *Node = undefined;
    defer child.deinit(testing.allocator);

    const node_path = "abc";

    node = try node.compress(testing.allocator, node_path, &child);

    try testing.expect(node.is_compressed);
    try testing.expectEqualStrings(node_path, node.path());
    try testing.expectEqual(@intCast(u29, node_path.len), node.size);
}

test "walk compressed node" {
    var node = try Node.init(testing.allocator, 0, false);
    defer node.deinit(testing.allocator);

    var child: *Node = undefined;
    defer child.deinit(testing.allocator);

    const node_path = "abc";

    node = try node.compress(testing.allocator, node_path, &child);

    try testing.expect(node.is_compressed);
    try testing.expectEqualStrings(node_path, node.path());
    try testing.expectEqual(@intCast(u29, node_path.len), node.size);

    var trie: Trie = .{ .head = node };
    var stop_node: *Node = undefined;
    var parent_link: **Node = undefined;
    var split_pos: usize = 0;

    try testing.expectEqual(@as(usize, 3), try trie.walk(node_path[0..3], .{
        .stop_node = &stop_node,
        .parent_link_node = &parent_link,
        .split_pos = &split_pos,
    }));
    try testing.expectEqual(child, stop_node);
    try testing.expectEqual(&trie.head.children()[0], parent_link);
    try testing.expectEqual(@as(usize, 0), split_pos);

    try testing.expectEqual(@as(usize, 2), try trie.walk(node_path[0..2], .{
        .stop_node = &stop_node,
        .parent_link_node = &parent_link,
        .split_pos = &split_pos,
    }));
    try testing.expectEqual(node, stop_node);
    try testing.expectEqual(&trie.head, parent_link);
    try testing.expectEqual(@as(usize, 2), split_pos);

    try testing.expectEqual(@as(usize, 1), try trie.walk(node_path[0..1], .{
        .stop_node = &stop_node,
        .parent_link_node = &parent_link,
        .split_pos = &split_pos,
    }));
    try testing.expectEqual(node, stop_node);
    try testing.expectEqual(&trie.head, parent_link);
    try testing.expectEqual(@as(usize, 1), split_pos);
}

test "insert: overwrite existing key" {
    const node_path = "abc";

    var trie = trie: {
        var node = try Node.init(testing.allocator, 0, false);
        errdefer node.deallocate(testing.allocator);

        var child: *Node = undefined;
        node = try node.compress(testing.allocator, node_path, &child);

        try testing.expect(node.is_compressed);
        try testing.expectEqualStrings(node_path, node.path());
        try testing.expectEqual(@intCast(u29, node_path.len), node.size);
        break :trie Trie{ .head = node, .num_nodes = 2 };
    };
    defer trie.deinit(testing.allocator);

    // sanity check: no value set beforehand, find should return null
    try testing.expectEqual(@as(?Data, null), trie.find(node_path));

    // set to 0xdeadbeef, overwrite = false
    try testing.expect(try trie.insert(testing.allocator, node_path, @intToPtr(Data, 0xdeadbeef), .{}));
    try testing.expectEqual(@intToPtr(?Data, 0xdeadbeef), trie.find(node_path));

    // set to null value, overwrite = false
    try testing.expect(!try trie.insert(testing.allocator, node_path, null, .{}));
    try testing.expectEqual(@intToPtr(?Data, 0xdeadbeef), trie.find(node_path));

    // set to null value, overwrite = true
    var old_data: ?Data = null;
    try testing.expect(!try trie.insert(testing.allocator, node_path, null, .{ .old = &old_data, .overwrite = true }));
    try testing.expectEqual(@intToPtr(?Data, 0xdeadbeef), old_data);
    try testing.expectEqual(@as(?Data, null), trie.find(node_path));
}

test "insert: split existing compressed node into prefix, split, and postfix nodes" {
    var trie = try Trie.init(testing.allocator);
    defer trie.deinit(testing.allocator);

    try testing.expect(try trie.insert(testing.allocator, "hello world", @intToPtr(Data, 0xaeadbeef), .{}));
    try testing.expectEqual(@intToPtr(?Data, 0xaeadbeef), trie.find("hello world"));

    try testing.expect(try trie.insert(testing.allocator, "hello borld", @intToPtr(Data, 0xbeadbeef), .{}));

    try testing.expectEqual(@intToPtr(?Data, 0xaeadbeef), trie.find("hello world"));
    try testing.expectEqual(@intToPtr(?Data, 0xbeadbeef), trie.find("hello borld"));
}

test "insert and remove" {
    var trie = try Trie.init(testing.allocator);
    defer trie.deinit(testing.allocator);

    // insert 'hello world', 'hello borld'
    // remove 'hello world', 'hello borld'

    try testing.expect(try trie.insert(testing.allocator, "hello world", @intToPtr(Data, 0xaeadbeef), .{}));
    try testing.expect(try trie.insert(testing.allocator, "hello borld", @intToPtr(Data, 0xbeadbeef), .{}));

    try testing.expectEqual(@intToPtr(?Data, 0xaeadbeef), trie.find("hello world"));
    try testing.expectEqual(@intToPtr(?Data, 0xbeadbeef), trie.find("hello borld"));

    try testing.expect(try trie.remove(testing.allocator, "hello world", null));

    try testing.expectEqual(@as(?Data, null), trie.find("hello world"));
    try testing.expectEqual(@intToPtr(?Data, 0xbeadbeef), trie.find("hello borld"));

    try testing.expect(try trie.remove(testing.allocator, "hello borld", null));

    try testing.expectEqual(@as(?Data, null), trie.find("hello world"));
    try testing.expectEqual(@as(?Data, null), trie.find("hello borld"));

    // insert 'hello world', 'hello borld'
    // remove 'hello borld', 'hello world'

    try testing.expect(try trie.insert(testing.allocator, "hello world", @intToPtr(Data, 0xaeadbeef), .{}));
    try testing.expect(try trie.insert(testing.allocator, "hello borld", @intToPtr(Data, 0xbeadbeef), .{}));

    try testing.expectEqual(@intToPtr(?Data, 0xaeadbeef), trie.find("hello world"));
    try testing.expectEqual(@intToPtr(?Data, 0xbeadbeef), trie.find("hello borld"));

    try testing.expect(try trie.remove(testing.allocator, "hello borld", null));

    try testing.expectEqual(@intToPtr(?Data, 0xaeadbeef), trie.find("hello world"));
    try testing.expectEqual(@as(?Data, null), trie.find("hello borld"));

    try testing.expect(try trie.remove(testing.allocator, "hello world", null));

    try testing.expectEqual(@as(?Data, null), trie.find("hello world"));
    try testing.expectEqual(@as(?Data, null), trie.find("hello borld"));

    try testing.expectEqual(@as(usize, 1), trie.num_nodes);
    try testing.expectEqual(@as(usize, 0), trie.num_elements);
}

test "insert order" {
    var trie = try Trie.init(testing.allocator);
    defer trie.deinit(testing.allocator);

    try testing.expect(try trie.insert(testing.allocator, "z", null, .{}));
    try testing.expect(try trie.insert(testing.allocator, "y", null, .{}));
    try testing.expect(try trie.insert(testing.allocator, "x", null, .{}));
    try testing.expect(try trie.insert(testing.allocator, "a", null, .{}));

    var key = std.ArrayList(u8).init(testing.allocator);
    defer key.deinit();

    try testing.expectEqual(@as(?Data, null), try trie.first(&key));
    try testing.expectEqualStrings("a", key.items);
    try testing.expect(try trie.remove(testing.allocator, key.items, null));

    try testing.expectEqual(@as(?Data, null), try trie.first(&key));
    try testing.expectEqualStrings("x", key.items);
    try testing.expect(try trie.remove(testing.allocator, key.items, null));

    try testing.expectEqual(@as(?Data, null), try trie.first(&key));
    try testing.expectEqualStrings("y", key.items);
    try testing.expect(try trie.remove(testing.allocator, key.items, null));

    try testing.expectEqual(@as(?Data, null), try trie.first(&key));
    try testing.expectEqualStrings("z", key.items);
    try testing.expect(try trie.remove(testing.allocator, key.items, null));
}
