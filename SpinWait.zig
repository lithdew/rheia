const std = @import("std");

const os = std.os;
const atomic = std.atomic;

const SpinWait = @This();

counter: u5 = 0,

pub inline fn reset(self: *SpinWait) void {
    self.counter = 0;
}

pub inline fn spin(self: *SpinWait) bool {
    if (self.counter >= 10) return false;
    self.counter += 1;
    if (self.counter <= 3) {
        cpuRelax(@as(u32, 1) << self.counter);
    } else {
        os.sched_yield() catch {};
    }
    return true;
}

pub inline fn spinNoYield(self: *SpinWait) void {
    self.counter += 1;
    if (self.counter > 10) {
        self.counter = 10;
    }
    cpuRelax(@as(u32, 1) << self.counter);
}

inline fn cpuRelax(iterations: u32) void {
    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        atomic.spinLoopHint();
    }
}
