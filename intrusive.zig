const std = @import("std");

const meta = std.meta;

pub fn SinglyLinkedList(comptime T: type, comptime next_field: meta.FieldEnum(T)) type {
    const next = meta.fieldInfo(T, next_field).name;

    return struct {
        const Self = @This();

        head: ?*T = null,

        pub fn prepend(self: *Self, value: *T) void {
            @field(value, next) = self.head;
            self.head = value;
        }

        pub fn popFirst(self: *Self) ?*T {
            const head = self.head orelse return null;
            self.head = @field(head, next);
            @field(head, next) = null;
            return head;
        }
    };
}

pub fn DoublyLinkedDeque(comptime T: type, comptime next_field: meta.FieldEnum(T), comptime prev_field: meta.FieldEnum(T)) type {
    const next = meta.fieldInfo(T, next_field).name;
    const prev = meta.fieldInfo(T, prev_field).name;

    return struct {
        const Self = @This();

        head: ?*T = null,
        tail: ?*T = null,

        pub fn append(self: *Self, value: *T) void {
            if (self.tail) |tail| {
                @field(tail, next) = value;
            } else {
                self.head = value;
            }
            @field(value, prev) = self.tail;
            @field(value, next) = null;
            self.tail = value;
        }

        pub fn popFirst(self: *Self) ?*T {
            const head = self.head orelse return null;
            if (@field(head, next)) |next_value| {
                @field(next_value, prev) = null;
            } else {
                self.tail = null;
            }
            self.head = @field(head, next);
            @field(head, next) = null;
            @field(head, prev) = null;
            return head;
        }

        pub fn remove(self: *Self, value: *T) bool {
            if (self.head == null) {
                return false;
            }

            if (self.head != value and @field(value, next) == null and @field(value, prev) == null) {
                return false;
            }

            if (@field(value, next)) |next_value| {
                @field(next_value, prev) = @field(value, prev);
            } else {
                self.tail = @field(value, prev);
            }
            if (@field(value, prev)) |prev_value| {
                @field(prev_value, next) = @field(value, next);
            } else {
                self.head = @field(value, next);
            }

            @field(value, next) = null;
            @field(value, prev) = null;

            return true;
        }
    };
}

pub fn SinglyLinkedDeque(comptime T: type, comptime next_field: meta.FieldEnum(T)) type {
    const next = meta.fieldInfo(T, next_field).name;

    return struct {
        const Self = @This();

        head: ?*T = null,
        tail: ?*T = null,

        pub fn prepend(self: *Self, value: *T) void {
            if (self.head == null) self.tail = value;
            @field(value, next_field_nnextame) = self.head;
            self.head = value;
        }

        pub fn append(self: *Self, value: *T) void {
            if (self.tail) |tail| {
                @field(tail, next) = value;
            } else {
                self.head = value;
            }
            self.tail = value;
        }

        pub fn popFirst(self: *Self) ?*T {
            const head = self.head orelse return null;
            self.head = @field(head, next);
            @field(head, next) = null;
            return head;
        }
    };
}