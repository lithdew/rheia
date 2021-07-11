const std = @import("std");

const os = std.os;
const io = @import("io.zig");
const mem = std.mem;

const assert = std.debug.assert;

const Runtime = @This();

gpa: std.heap.GeneralPurposeAllocator(.{}),

worker_count: usize,
io_workers: std.ArrayListUnmanaged(io.Worker),
io_worker_threads: std.ArrayListUnmanaged(std.Thread),

signal: struct {
    fd: os.fd_t,
    set: os.sigset_t,
    prev_set: os.sigset_t,
},

pub fn init() !Runtime {
    var runtime: Runtime = undefined;

    runtime.gpa = .{};

    runtime.worker_count = try std.Thread.getCpuCount();
    if (runtime.worker_count <= 1) return error.SingleThreaded;

    try runtime.initSignalHandler();
    try runtime.initIoWorkers(runtime.worker_count);

    return runtime;
}

pub fn deinit(self: *Runtime) void {
    self.io_worker_threads.deinit(&self.gpa.allocator);

    for (self.io_workers.items) |*io_worker| io_worker.deinit();
    self.io_workers.deinit(&self.gpa.allocator);

    assert(!self.gpa.deinit());
}

pub fn start(self: *Runtime) !void {
    try self.startSignalHandler();
    try self.startIoWorkers();
}

pub fn shutdown(self: *Runtime) void {
    for (self.io_workers.items) |*io_worker| io_worker.shutdown();
}

pub fn waitForShutdown(self: *Runtime) void {
    for (self.io_worker_threads.items) |*io_worker_thread| io_worker_thread.join();
}

pub fn waitForSignal(self: *Runtime) !void {
    var info: os.signalfd_siginfo = undefined;

    var bytes_read: usize = 0;
    while (bytes_read < @sizeOf(os.signalfd_siginfo)) {
        const num_bytes = try self.io_workers.items[0].loop.read(self.signal.fd, mem.asBytes(&info), 0);
        if (num_bytes == 0) return error.EndOfFile;
        bytes_read += num_bytes;
    }

    if (os.system.sigprocmask(os.SIG_SETMASK, &self.signal.prev_set, null) != 0) {
        return error.SignalMaskFailed;
    }
}

fn initSignalHandler(self: *Runtime) !void {
    self.signal.set = mem.zeroes(os.sigset_t);
    os.system.sigaddset(&self.signal.set, os.SIGINT);
    os.system.sigaddset(&self.signal.set, os.SIGQUIT);

    if (os.system.sigprocmask(os.SIG_BLOCK, &self.signal.set, &self.signal.prev_set) != 0) {
        return error.SignalMaskFailed;
    }
    errdefer assert(os.system.sigprocmask(os.SIG_SETMASK, &self.signal.prev_set, null) == 0);

    self.signal.fd = try os.signalfd(-1, &self.signal.set, os.O_CLOEXEC);
    errdefer os.close(self.signal.fd);
}

fn startSignalHandler(_: *Runtime) !void {}

fn initIoWorkers(self: *Runtime, count: usize) !void {
    self.io_workers = try std.ArrayListUnmanaged(io.Worker).initCapacity(&self.gpa.allocator, count);
    errdefer self.io_workers.deinit(&self.gpa.allocator);

    self.io_worker_threads = try std.ArrayListUnmanaged(std.Thread).initCapacity(&self.gpa.allocator, count - 1);
    errdefer self.io_worker_threads.deinit(&self.gpa.allocator);

    var index: usize = 0;
    errdefer for (self.io_workers.items[0..index]) |*io_worker| io_worker.deinit();

    while (index < count) : (index += 1) {
        try self.io_workers.addOneAssumeCapacity().init();
    }
}

fn startIoWorkers(self: *Runtime) !void {
    var thread_index: usize = 0;
    errdefer for (self.io_worker_threads.items[0..thread_index]) |*io_worker_thread| io_worker_thread.join();
    errdefer for (self.io_workers.items) |*io_worker| io_worker.shutdown();

    while (thread_index < self.io_workers.items.len - 1) : (thread_index += 1) {
        const io_worker = &self.io_workers.items[thread_index + 1];
        self.io_worker_threads.addOneAssumeCapacity().* = try std.Thread.spawn(.{}, io.Worker.run, .{io_worker});
    }
}
