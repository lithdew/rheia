const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("rheia", "main.zig");
    for ([_]*std.build.LibExeObjStep{exe}) |step| {
        step.addCSourceFile("zig-sqlite/c/sqlite3.c", &.{});
        step.addIncludePath("zig-sqlite/c");
        step.linkLibC();

        step.setTarget(target);
        step.setBuildMode(mode);
        step.install();
    }
}
