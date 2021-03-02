const std = @import("std");
const Builder = std.build.Builder;
const pkgs = @import("gyro").pkgs;

pub fn build(b: *Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const progs = .{
        .server = b.addExecutable("astrolabe", "src/main.zig"),
        .adduser = b.addExecutable("astro-adduser", "src/adduser.zig"),
        .publish = b.addExecutable("astro-publish", "src/publish.zig"),
    };

    inline for (std.meta.fields(@TypeOf(progs))) |field| {
        @field(progs, field.name).setTarget(target);
        @field(progs, field.name).setBuildMode(mode);
        @field(progs, field.name).install();
        pkgs.addAllTo(@field(progs, field.name));
    }

    const run_cmd = progs.server.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the server");
    run_step.dependOn(&run_cmd.step);
}
