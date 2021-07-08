const std = @import("std");

const io = @import("io.zig");
const mem = std.mem;

const assert = std.debug.assert;

pub const Runtime = struct {
    gpa: std.heap.GeneralPurposeAllocator(.{}),

    worker_count: usize,
    io_workers: std.ArrayListUnmanaged(io.Worker),
    io_worker_threads: std.ArrayListUnmanaged(std.Thread),

    pub fn init() !Runtime {
        var runtime: Runtime = undefined;

        runtime.gpa = .{};

        runtime.worker_count = try std.Thread.getCpuCount();
        if (runtime.worker_count <= 1) return error.SingleThreaded;

        try runtime.initIoWorkers(runtime.worker_count);

        return runtime;
    }

    pub fn deinit(self: *Runtime) void {
        // TODO: signal to i/o worker thread to shutdown

        for (self.io_worker_threads.items) |*io_worker_thread| io_worker_thread.join();
        self.io_worker_threads.deinit(&self.gpa.allocator);

        for (self.io_workers.items) |*io_worker| io_worker.deinit();
        self.io_workers.deinit(&self.gpa.allocator);

        assert(!self.gpa.deinit());
    }

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

        // TODO: signal to i/o worker thread to shutdown

        var thread_index: usize = 0;
        errdefer for (self.io_worker_threads.items[0..thread_index]) |*io_worker_thread| io_worker_thread.join();

        while (thread_index < count - 1) : (thread_index += 1) {
            const io_worker = &self.io_workers.items[thread_index + 1];
            self.io_worker_threads.addOneAssumeCapacity().* = try std.Thread.spawn(.{}, io.Worker.run, .{io_worker});
        }
    }
};
