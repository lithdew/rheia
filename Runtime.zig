const std = @import("std");

const os = std.os;
const mem = std.mem;
const builtin = std.builtin;

const assert = std.debug.assert;

const Worker = @import("Worker.zig");

const Runtime = @This();

gpa_instance: std.heap.GeneralPurposeAllocator(.{}),
gpa: *mem.Allocator,

worker_count: usize,
workers: std.ArrayListUnmanaged(Worker),
worker_threads: std.ArrayListUnmanaged(std.Thread),

signal: struct {
    fd: os.fd_t,
    set: os.sigset_t,
    prev_set: os.sigset_t,
},

pub fn init(self: *Runtime) !void {
    self.gpa_instance = .{};
    if (builtin.link_libc) {
        self.gpa_instance.backing_allocator = std.heap.c_allocator;
    }
    if (builtin.link_libc) {
        self.gpa = std.heap.c_allocator;
    } else {
        self.gpa = &self.gpa_instance.allocator;
    }

    self.worker_count = if (builtin.single_threaded) 1 else try std.Thread.getCpuCount();
    if (self.worker_count == 0) return error.NoWorkers;

    try self.initSignalHandler();
    try self.initWorkers(self.worker_count);
}

pub fn deinit(self: *Runtime) void {
    self.worker_threads.deinit(self.gpa);

    for (self.workers.items) |*worker| {
        worker.deinit(self.gpa);
    }
    self.workers.deinit(self.gpa);

    assert(!self.gpa_instance.deinit());
}

pub fn start(self: *Runtime) !void {
    try self.startSignalHandler();
    try self.startWorkers();
}

pub fn shutdown(self: *Runtime) void {
    for (self.workers.items) |*worker| worker.shutdown();
}

pub fn waitForShutdown(self: *Runtime) void {
    for (self.worker_threads.items) |*worker_thread| worker_thread.join();
}

pub fn waitForSignal(self: *Runtime) !void {
    var info: os.signalfd_siginfo = undefined;

    var bytes_read: usize = 0;
    while (bytes_read < @sizeOf(os.signalfd_siginfo)) {
        const num_bytes = try self.workers.items[0].loop.read(self.signal.fd, mem.asBytes(&info), 0);
        if (num_bytes == 0) return error.EndOfFile;
        bytes_read += num_bytes;
    }

    if (os.system.sigprocmask(os.SIG_SETMASK, &self.signal.prev_set, null) != 0) {
        return error.SignalMaskFailed;
    }
}

pub fn yield(self: *Runtime, from: usize, to: usize) void {
    var task: Worker.Task = .{ .value = @frame() };
    suspend self.schedule(from, to, &task);
}

pub fn schedule(self: *Runtime, from: usize, to: usize, task: *Worker.Task) void {
    self.workers.items[to].task_queues.items[from].push(task);
    if (from != to) self.workers.items[to].loop.notify();
}

fn initSignalHandler(self: *Runtime) !void {
    self.signal.set = mem.zeroes(os.sigset_t);
    os.linux.sigaddset(&self.signal.set, os.SIGINT);
    os.linux.sigaddset(&self.signal.set, os.SIGQUIT);

    if (os.system.sigprocmask(os.SIG_BLOCK, &self.signal.set, &self.signal.prev_set) != 0) {
        return error.SignalMaskFailed;
    }
    errdefer assert(os.system.sigprocmask(os.SIG_SETMASK, &self.signal.prev_set, null) == 0);

    self.signal.fd = try os.signalfd(-1, &self.signal.set, os.O_CLOEXEC);
    errdefer os.close(self.signal.fd);
}

fn startSignalHandler(_: *Runtime) !void {}

fn initWorkers(self: *Runtime, count: usize) !void {
    self.workers = try std.ArrayListUnmanaged(Worker).initCapacity(self.gpa, count);
    errdefer self.workers.deinit(self.gpa);

    self.worker_threads = try std.ArrayListUnmanaged(std.Thread).initCapacity(self.gpa, count - 1);
    errdefer self.worker_threads.deinit(self.gpa);

    var index: usize = 0;
    errdefer for (self.workers.items[0..index]) |*worker| worker.deinit(self.gpa);

    while (index < count) : (index += 1) {
        try self.workers.addOneAssumeCapacity().init(self.gpa, self.workers.items.ptr[0..count], index);
    }
}

fn startWorkers(self: *Runtime) !void {
    if (builtin.single_threaded) return;

    var thread_index: usize = 0;
    errdefer for (self.worker_threads.items[0..thread_index]) |*worker_thread| worker_thread.join();
    errdefer for (self.workers.items) |*worker| worker.shutdown();

    while (thread_index < self.workers.items.len - 1) : (thread_index += 1) {
        const worker = &self.workers.items[thread_index + 1];
        self.worker_threads.addOneAssumeCapacity().* = try std.Thread.spawn(.{}, Worker.run, .{worker});
    }
}
