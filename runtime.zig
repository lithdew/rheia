const std = @import("std");

const os = std.os;
const mem = std.mem;
const meta = std.meta;
const math = std.math;
const mpsc = @import("mpsc.zig");
const builtin = std.builtin;

const Atomic = std.atomic.Atomic;
const Socket = std.x.os.Socket;

const Ring = std.os.linux.IO_Uring;
const Submission = std.os.linux.io_uring_sqe;
const Completion = std.os.linux.io_uring_cqe;

const SinglyLinkedDeque = @import("intrusive.zig").SinglyLinkedDeque;

const assert = std.debug.assert;

// zig fmt: off

var instance: Runtime = undefined;

pub fn init() !void    { return instance.init();     }
pub fn deinit() void   { return instance.deinit();   }
pub fn start() !void   { return instance.start();    }
pub fn shutdown() void { return instance.shutdown(); }
pub fn join() void     { return instance.join();     }

pub fn waitForSignal() !void { return instance.waitForSignal(); }

pub fn getAllocator() *mem.Allocator { return instance.gpa;         }
pub fn getNumWorkers() usize         { return instance.workers.len; }
pub fn getCurrentWorkerId() usize    { return Worker.current.?.id;  }

pub fn run() !void                             { return Worker.current.?.run();                                            }
pub fn yield(to: usize) void                   { return instance.yield(Worker.current.?.id, to);                           }
pub fn schedule(task: *Task) void              { return instance.schedule(Worker.current.?.id, Worker.current.?.id, task); }
pub fn scheduleTo(to: usize, task: *Task) void { return instance.schedule(Worker.current.?.id, to, task);                  }

pub fn cancel(target_request: *Request) void                                                         { return Worker.current.?.cancel(target_request);             }
pub fn read(request: *Request, fd: os.fd_t, buffer: []u8, offset: u64) !usize                        { return Worker.current.?.read(request, fd, buffer, offset);  }
pub fn recv(request: *Request, fd: os.socket_t, buffer: []u8, flags: u32) !usize                     { return Worker.current.?.recv(request, fd, buffer, flags);   }
pub fn write(request: *Request, fd: os.fd_t, buffer: []const u8, offset: u64) !usize                 { return Worker.current.?.write(request, fd, buffer, offset); }
pub fn send(request: *Request, fd: os.socket_t, buffer: []const u8, flags: u32) !usize               { return Worker.current.?.send(request, fd, buffer, flags);   }
pub fn connect(request: *Request, fd: os.socket_t, address: Socket.Address) !void                    { return Worker.current.?.connect(request, fd, address);      }
pub fn accept(request: *Request, fd: os.socket_t, flags: Flags(Socket.InitFlags)) !Socket.Connection { return Worker.current.?.accept(request, fd, flags);         }
pub fn timeout(request: *Request, params: Request.Timeout) !void                                     { return Worker.current.?.timeout(request, params);           }

// zig fmt: on

pub const Task = struct {
    pub const Queue = mpsc.UnboundedStack(Task, .next);

    next: ?*Task = null,
    frame: anyframe,
};

pub const Request = struct {
    pub const Deque = SinglyLinkedDeque(Request, .next);

    pub const Timeout = struct {
        seconds: i64 = 0,
        nanoseconds: i64 = 0,
        mode: enum(u32) {
            relative = 0,
            absolute = os.IORING_TIMEOUT_ABS,
        } = .relative,
    };

    next: ?*Request = null,
    result: ?isize = null,
    frame: anyframe = undefined,
};

fn Flags(comptime T: type) type {
    return std.enums.EnumFieldStruct(T, bool, false);
}

pub const Runtime = struct {
    gpa_instance: std.heap.GeneralPurposeAllocator(.{}),
    gpa: *mem.Allocator,

    workers: []Worker,
    worker_threads: []std.Thread,

    signal: struct {
        fd: os.fd_t,
        set: os.sigset_t,
        prev_set: os.sigset_t,
    },

    pub fn init(self: *Runtime) !void {
        self.gpa_instance = .{};
        if (builtin.link_libc) {
            self.gpa_instance.backing_allocator = std.heap.c_allocator;
            self.gpa = std.heap.c_allocator;
        } else {
            self.gpa = &self.gpa_instance.allocator;
        }

        var num_workers: usize = if (builtin.single_threaded) 1 else try std.Thread.getCpuCount();
        num_workers = math.max(1, num_workers / 2);

        try self.initSignalHandler();
        try self.initWorkers(num_workers);
    }

    pub fn deinit(self: *Runtime) void {
        self.gpa.free(self.worker_threads);

        for (self.workers) |*worker| {
            worker.deinit(self.gpa);
        }
        self.gpa.free(self.workers);

        assert(!self.gpa_instance.deinit());
    }

    pub fn start(self: *Runtime) !void {
        try self.startSignalHandler();
        try self.startWorkers();
    }

    pub fn shutdown(self: *Runtime) void {
        for (self.workers) |*worker| {
            worker.shutdown();
        }
    }

    pub fn join(self: *Runtime) void {
        for (self.worker_threads) |*worker_thread| {
            worker_thread.join();
        }
    }

    pub fn waitForSignal(self: *Runtime) !void {
        var info: os.signalfd_siginfo = undefined;
        var request: Request = .{};

        var bytes_read: usize = 0;
        while (bytes_read < @sizeOf(os.signalfd_siginfo)) {
            const num_bytes = try Worker.current.?.read(&request, self.signal.fd, mem.asBytes(&info), 0);
            if (num_bytes == 0) return error.EndOfFile;
            bytes_read += num_bytes;
        }

        if (os.system.sigprocmask(os.SIG_SETMASK, &self.signal.prev_set, null) != 0) {
            return error.SignalMaskFailed;
        }
    }

    pub fn yield(self: *Runtime, from: usize, to: usize) void {
        const same_worker = from == to;
        if (same_worker) return;

        var task: Task = .{ .frame = @frame() };
        suspend {
            self.workers[to].task_queues[from].push(&task);
            if (!same_worker) self.workers[to].notifier.set();
        }
    }

    pub fn schedule(self: *Runtime, from: usize, to: usize, task: *Task) void {
        const same_worker = from == to;
        self.workers[to].task_queues[from].push(task);
        if (!same_worker) self.workers[to].notifier.set();
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
        self.workers = try self.gpa.alloc(Worker, count);
        errdefer self.gpa.free(self.workers);

        self.worker_threads = try self.gpa.alloc(std.Thread, count - 1);
        errdefer self.gpa.free(self.worker_threads);

        var index: usize = 0;
        errdefer for (self.workers[0..index]) |*worker| worker.deinit(self.gpa);

        while (index < count) : (index += 1) {
            try self.workers[index].init(self.gpa, self.workers, index);
        }

        Worker.current = &self.workers[0];
    }

    fn startWorkers(self: *Runtime) !void {
        if (builtin.single_threaded) return;

        var thread_index: usize = 0;
        errdefer for (self.worker_threads[0..thread_index]) |*worker_thread| worker_thread.join();
        errdefer for (self.workers) |*worker| worker.shutdown();

        while (thread_index < self.workers.len - 1) : (thread_index += 1) {
            const worker = &self.workers[thread_index + 1];
            self.worker_threads[thread_index] = try std.Thread.spawn(.{}, Worker.run, .{worker});
        }
    }
};

pub const Worker = struct {
    pub threadlocal var current: ?*Worker = null;

    pub const Notifier = struct {
        armed: Atomic(bool) = .{ .value = false },
        count: u64 = math.maxInt(u64),
        fd: os.fd_t,

        pub fn init() !Notifier {
            return Notifier{ .fd = try os.eventfd(0, os.O_CLOEXEC) };
        }

        pub fn deinit(self: *Notifier) void {
            os.close(self.fd);
        }

        pub fn set(self: *Notifier) void {
            if (self.armed.compareAndSwap(true, false, .Monotonic, .Monotonic) != null) {
                return;
            }
            const bytes_written = os.write(self.fd, mem.asBytes(&@as(u64, 1))) catch 0;
            assert(bytes_written == @sizeOf(u64));
        }

        pub fn reset(self: *Notifier, ring: *Ring) bool {
            if (self.armed.load(.Monotonic) or self.count == 0) {
                return false;
            }
            self.count = 0;
            if ((ring.read(0, self.fd, mem.asBytes(&self.count), 0) catch null) == null) {
                return false;
            }
            self.armed.store(true, .Monotonic);
            return true;
        }
    };

    const log = std.log.scoped(.worker);

    id: usize,
    shutdown_requested: Atomic(bool) = .{ .value = false },

    task_queues: []Task.Queue = undefined,

    ring: Ring = undefined,
    notifier: Notifier = undefined,
    submissions: Request.Deque = .{},
    completions: Request.Deque = .{},

    pub fn init(self: *Worker, gpa: *mem.Allocator, workers: []const Worker, id: usize) !void {
        self.* = .{ .id = id };

        self.task_queues = try gpa.alloc(Task.Queue, workers.len);
        errdefer gpa.free(self.task_queues);

        var task_queue_index: usize = 0;
        while (task_queue_index < self.task_queues.len) : (task_queue_index += 1) {
            self.task_queues[task_queue_index] = .{};
        }

        var params = switch (id) {
            0 => mem.zeroInit(os.linux.io_uring_params, .{
                .flags = 0,
                .sq_thread_cpu = @intCast(u32, id),
                .sq_thread_idle = 1000,
            }),
            else => mem.zeroInit(os.linux.io_uring_params, .{
                .flags = os.IORING_SETUP_ATTACH_WQ,
                .wq_fd = @intCast(u32, workers[0].ring.fd),
                .sq_thread_cpu = @intCast(u32, id),
                .sq_thread_idle = 1000,
            }),
        };

        self.ring = try Ring.init_params(4096, &params);
        errdefer self.ring.deinit();

        self.notifier = try Notifier.init();
        errdefer self.notifier.deinit();
    }

    pub fn deinit(self: *Worker, gpa: *mem.Allocator) void {
        self.ring.deinit();
        self.notifier.deinit();

        gpa.free(self.task_queues);
    }

    pub fn shutdown(self: *Worker) void {
        self.shutdown_requested.store(true, .Release);
        self.notifier.set();
    }

    pub fn run(self: *Worker) !void {
        Worker.current = self;

        log.debug("worker {} started", .{self.id});
        defer log.debug("worker {} is done", .{self.id});

        var timer = try std.time.Timer.start();
        var num_tasks: usize = 0;
        var num_io_tasks: usize = 0;

        while (true) {
            const num_processed_tasks = self.pollTasks();
            const num_processed_io_tasks = try self.pollIoTasks(num_processed_tasks == 0);

            num_tasks += num_processed_tasks;
            num_io_tasks += num_processed_io_tasks;

            if (timer.read() > 1 * std.time.ns_per_s) {
                log.debug("{}: processed {} task(s) and {} i/o task(s)", .{
                    self.id,
                    num_tasks,
                    num_io_tasks,
                });

                num_tasks = 0;
                num_io_tasks = 0;

                timer.reset();
            }

            if (shutdown: {
                if (!self.shutdown_requested.load(.Acquire)) {
                    break :shutdown false;
                }

                if (!self.submissions.isEmpty() or !self.completions.isEmpty()) {
                    break :shutdown false;
                }

                if (num_processed_io_tasks > 0) {
                    break :shutdown false;
                }

                break :shutdown true;
            }) {
                break;
            }
        }
    }

    pub fn pollTasks(self: *Worker) usize {
        var num_tasks_processed: usize = 0;

        for (self.task_queues) |*task_queue| {
            var it = task_queue.popBatch();
            while (it) |node| : (num_tasks_processed += 1) {
                it = node.next;
                resume node.frame;
            }
        }

        return num_tasks_processed;
    }

    pub fn pollIoTasks(self: *Worker, blocking: bool) !usize {
        var completions: [4096]Completion = undefined;
        var count: usize = 0;

        _ = self.ring.submit_and_wait(num_waiters: {
            if (!blocking or !self.submissions.isEmpty() or !self.completions.isEmpty()) {
                break :num_waiters 0;
            }

            if (self.notifier.reset(&self.ring)) {
                break :num_waiters 0;
            }

            break :num_waiters 1;
        }) catch |err| switch (err) {
            error.CompletionQueueOvercommitted, error.SystemResources => 0,
            error.SignalInterrupt => return count,
            else => return err,
        };

        const num_completions = try self.ring.copy_cqes(&completions, 0);
        for (completions[0..num_completions]) |completion| {
            if (completion.user_data == 0) {
                continue;
            }

            const waiter = @intToPtr(*Request, completion.user_data);
            waiter.result = completion.res;
            self.completions.append(waiter);
        }

        var it: Request.Deque = .{};

        mem.swap(Request.Deque, &it, &self.submissions);
        while (it.popFirst()) |request| : (count += 1) {
            resume request.frame;
        }

        if (count > 0) {
            return count;
        }

        mem.swap(Request.Deque, &it, &self.completions);
        while (it.popFirst()) |request| : (count += 1) {
            resume request.frame;
        }

        return count;
    }

    pub fn read(self: *Worker, request: *Request, fd: os.fd_t, buffer: []u8, offset: u64) !usize {
        while (true) {
            const result = try self.submitAndWait(request, Ring.read, .{ fd, buffer, offset });
            if (!try @import("os.zig").handleReadError(result)) {
                continue;
            }
            return @intCast(usize, result);
        }
    }

    pub fn write(self: *Worker, request: *Request, fd: os.fd_t, buffer: []const u8, offset: u64) !usize {
        while (true) {
            const result = try self.submitAndWait(request, Ring.write, .{ fd, buffer, offset });
            if (!try @import("os.zig").handleWriteError(result)) {
                continue;
            }
            return @intCast(usize, result);
        }
    }

    pub fn recv(self: *Worker, request: *Request, fd: os.socket_t, buffer: []u8, flags: u32) !usize {
        while (true) {
            const result = try self.submitAndWait(request, Ring.recv, .{ fd, buffer, flags });
            if (!try @import("os.zig").handleRecvError(result)) {
                continue;
            }
            return @intCast(usize, result);
        }
    }

    pub fn send(self: *Worker, request: *Request, fd: os.socket_t, buffer: []const u8, flags: u32) !usize {
        while (true) {
            const result = try self.submitAndWait(request, Ring.send, .{ fd, buffer, flags });
            if (!try @import("os.zig").handleSendError(result)) {
                continue;
            }
            return @intCast(usize, result);
        }
    }

    pub fn connect(self: *Worker, request: *Request, fd: os.socket_t, address: Socket.Address) !void {
        while (true) {
            const result = try self.submitAndWait(request, Ring.connect, .{
                fd,
                @ptrCast(*const os.sockaddr, &address.toNative()),
                address.getNativeSize(),
            });
            if (!try @import("os.zig").handleConnectError(result)) {
                continue;
            }
            return;
        }
    }

    pub fn accept(self: *Worker, request: *Request, fd: os.socket_t, flags: Flags(Socket.InitFlags)) !Socket.Connection {
        while (true) {
            var address: Socket.Address.Native.Storage = undefined;
            var address_len: u32 = @sizeOf(Socket.Address.Native.Storage);
            var raw_flags: u32 = 0;

            const set = std.EnumSet(Socket.InitFlags).init(flags);
            if (set.contains(.close_on_exec)) raw_flags |= os.SOCK_CLOEXEC;
            if (set.contains(.nonblocking)) raw_flags |= os.SOCK_NONBLOCK;

            const result = try self.submitAndWait(request, Ring.accept, .{ fd, @ptrCast(*os.sockaddr, &address), &address_len, raw_flags });
            if (!try @import("os.zig").handleAcceptError(result)) {
                continue;
            }

            const socket = Socket{ .fd = @intCast(os.socket_t, result) };
            const socket_address = Socket.Address.fromNative(@ptrCast(*os.sockaddr, &address));

            return Socket.Connection.from(socket, socket_address);
        }
    }

    pub fn timeout(self: *Worker, request: *Request, params: Request.Timeout) !void {
        while (true) {
            const timespec: os.__kernel_timespec = .{
                .tv_sec = params.seconds,
                .tv_nsec = params.nanoseconds,
            };

            const result = try self.submitAndWait(request, Ring.timeout, .{ &timespec, 0, @enumToInt(params.mode) });
            return switch (-result) {
                0 => {},
                os.ETIME => {},
                os.ECANCELED => error.Cancelled,
                else => |err| os.unexpectedErrno(err),
            };
        }
    }

    pub fn cancel(self: *Worker, target_request: *Request) void {
        var request: Request = .{};

        const result = self.submitAndWait(&request, ring_cancel, .{ @ptrToInt(target_request), 0 }) catch return;
        return switch (-result) {
            0, os.ENOENT => {},
            else => |err| std.debug.panic("{}", .{os.unexpectedErrno(err)}),
        };
    }

    fn ring_cancel(self: *Ring, user_data: u64, target_user_data: u64, flags: u32) !*Submission {
        const sqe = try self.get_sqe();
        io_uring_prep_cancel(sqe, target_user_data, flags);
        sqe.user_data = user_data;
        return sqe;
    }

    fn io_uring_prep_cancel(sqe: *Submission, user_data: u64, flags: u32) void {
        os.linux.io_uring_prep_rw(.ASYNC_CANCEL, sqe, -1, user_data, 0, 0);
        sqe.rw_flags = flags;
    }

    fn submitAndWait(self: *Worker, request: *Request, comptime function: anytype, params: anytype) !isize {
        request.* = .{ .frame = @frame() };

        var arguments: meta.ArgsTuple(@TypeOf(function)) = undefined;

        arguments[0] = &self.ring;
        arguments[1] = @ptrToInt(request);

        comptime var i = 0;
        inline while (i < params.len) : (i += 1) {
            arguments[2 + i] = params[i];
        }

        while (true) {
            var maybe_err: ?anyerror = null;
            suspend {
                maybe_err = blk: {
                    _ = @call(.{}, function, arguments) catch |err| {
                        self.submissions.append(request);
                        switch (err) {
                            error.SubmissionQueueFull => {},
                            else => break :blk err,
                        }
                    };
                    break :blk null;
                };
            }

            if (maybe_err) |err| {
                return err;
            }

            return request.result orelse continue;
        }
    }
};
