const std = @import("std");
const redis = @import("okredis");

const SET = redis.commands.strings.SET;
const INCR = redis.commands.strings.INCR;
const HSET = redis.commands.hashes.HSET;
const FV = redis.commands.hashes.utils.FV;
const OrErr = redis.types.OrErr;
const FixBuf = redis.types.FixBuf;
const Client = redis.Client;
const UserId = [32]u8;
const email_max_len = 320;
const username_max_len = 32;

// TODO: add email at some point to the schema
pub fn main() !void {
    var args = std.process.args();
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = &arena.allocator;

    _ = args.nextPosix(); // ignore name of the executable
    const username = args.nextPosix() orelse return error.NoUsername;

    var client: Client = undefined;
    try client.init(try std.net.connectUnixSocket("/var/run/redis/redis.sock"));
    defer client.close();

    const keys = .{
        .user = try std.fmt.allocPrint(allocator, "user:{s}", .{username}),
    };

    const reply = try client.trans(struct {
        user: OrErr(void),
    }, .{
        HSET.init(keys.user, &[_]FV{.{ .field = "username", .value = username }}),
    });
    errdefer {
        inline for (std.meta.fields(@TypeOf(reply))) |field| {
            if (@field(reply, field.name) == .Ok) {
                std.log.debug("removing {s}", .{field.name});
                client.send(void, .{ "DEL", @field(keys, field.name) }) catch {};
            }
        }
    }

    // rollback on error
    inline for (std.meta.fields(@TypeOf(reply))) |field| {
        if (@field(reply, field.name) != .Ok) {
            std.log.err("issue with {s}", .{field.name});

            return error.Redis;
        }
    }

    const path = try std.fs.path.join(allocator, &[_][]const u8{ "/var/www/archive/", username });
    std.fs.makeDirAbsolute(path) catch |err| {
        if (err != error.PathAlreadyExists)
            return err;
    };

    std.log.info("added user '{s}'", .{username});
}
