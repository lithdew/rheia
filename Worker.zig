const std = @import("std");

const os = std.os;
const mem = std.mem;
const testing = std.testing;

const mpsc = @import("mpsc.zig");

const assert = std.debug.assert;

const Loop = @import("Loop.zig");

const Atomic = std.atomic.Atomic;

const Worker = @This();

pub const Task = Worker.TaskQueue.Node;
pub const TaskQueue = mpsc.UnboundedStack(anyframe);

pub threadlocal var current: ?*Worker = null;

const log = std.log.scoped(.worker);

id: usize,
loop: Loop = undefined,
task_queues: std.ArrayListUnmanaged(Worker.TaskQueue) = undefined,
shutdown_requested: Atomic(bool) = .{ .value = false },

pub fn init(self: *Worker, gpa: *mem.Allocator, workers: []const Worker, id: usize) !void {
    self.* = .{ .id = id };

    var params = switch (id) {
        0 => mem.zeroInit(os.linux.io_uring_params, .{
            .flags = 0,
            .sq_thread_cpu = @intCast(u32, id),
            .sq_thread_idle = 1000,
        }),
        else => mem.zeroInit(os.linux.io_uring_params, .{
            .flags = os.IORING_SETUP_ATTACH_WQ,
            .wq_fd = @intCast(u32, workers[0].loop.ring.fd),
            .sq_thread_cpu = @intCast(u32, id),
            .sq_thread_idle = 1000,
        }),
    };

    try self.loop.init(&params);
    errdefer self.loop.deinit();

    self.task_queues = try std.ArrayListUnmanaged(Worker.TaskQueue).initCapacity(gpa, workers.len);
    errdefer self.task_queues.deinit(gpa);

    var task_queue_index: usize = 0;
    errdefer for (self.task_queues.items[0..task_queue_index]) |*task_queue| task_queue.deinit(gpa);

    while (task_queue_index < workers.len) : (task_queue_index += 1) {
        self.task_queues.addOneAssumeCapacity().* = .{};
    }
}

pub fn deinit(self: *Worker, gpa: *mem.Allocator) void {
    self.loop.deinit();
    self.task_queues.deinit(gpa);
}

pub fn shutdown(self: *Worker) void {
    self.shutdown_requested.store(true, .Release);
    self.loop.notify();
}

pub inline fn getCurrent() *Worker {
    return Worker.current orelse unreachable;
}

pub fn pollIncomingTasks(self: *Worker) usize {
    var num_tasks_processed: usize = 0;

    for (self.task_queues.items) |*task_queue| {
        var it = task_queue.popBatch();
        while (it) |node| : (num_tasks_processed += 1) {
            it = node.next;
            resume node.value;
        }
    }

    return num_tasks_processed;
}

pub fn pollEventLoop(self: *Worker, blocking: bool) !usize {
    return self.loop.poll(blocking);
}

pub fn run(self: *Worker) !void {
    Worker.current = self;

    log.debug("worker {} started", .{self.id});
    defer log.debug("worker {} is done", .{self.id});

    var timer = try std.time.Timer.start();
    var incoming_task_count: usize = 0;
    var event_loop_task_count: usize = 0;

    while (true) {
        const num_processed_incoming_tasks = self.pollIncomingTasks();
        const num_processed_event_loop_tasks = try self.pollEventLoop(num_processed_incoming_tasks == 0);

        incoming_task_count += num_processed_incoming_tasks;
        event_loop_task_count += num_processed_event_loop_tasks;

        if (timer.read() > 1 * std.time.ns_per_s) {
            log.info("worker {}: in the last second, processed {} incoming task(s) and {} event loop task(s)", .{
                self.id,
                incoming_task_count,
                event_loop_task_count,
            });
            incoming_task_count = 0;
            event_loop_task_count = 0;
            timer.reset();
        }

        if (shutdown: {
            if (num_processed_event_loop_tasks > 0) break :shutdown false;
            if (self.loop.hasPendingTasks()) break :shutdown false;
            if (!self.shutdown_requested.load(.Acquire)) break :shutdown false;
            break :shutdown true;
        }) {
            break;
        }
    }
}
