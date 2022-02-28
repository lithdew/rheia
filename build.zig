const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const node = b.addExecutable("rheia", "main.zig");
    const benchmark = b.addExecutable("rheia-bench", "bench.zig");
    for ([_]*std.build.LibExeObjStep{ node, benchmark }) |step| {
        step.addCSourceFile("zig-sqlite/c/sqlite3.c", &.{});
        step.addIncludePath("zig-sqlite/c");
        step.linkLibC();

        step.setTarget(target);
        step.setBuildMode(mode);
        step.install();
    }
}
