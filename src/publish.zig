const std = @import("std");
const redis = @import("okredis");
const version = @import("version");
const zzz = @import("zzz");
const tar = @import("tar");
usingnamespace @import("common.zig");

const GET = redis.commands.strings.GET;
const SET = redis.commands.strings.SET;
const FV = redis.commands.hashes.utils.FV;
const SADD = redis.commands.sets.SADD;
const SISMEMBER = redis.commands.sets.SISMEMBER;
const OrErr = redis.types.OrErr;
const FixBuf = redis.types.FixBuf;
const HSET = redis.commands.hashes.HSET;

const optional_fields = [_][]const u8{
    "description",
    "homepage_url",
    "source_url",
    "license",
};

pub fn serializeDepsToJson(
    arena: *std.heap.ArenaAllocator,
    root: *zzz.ZNode,
    tag: []const u8,
) !std.ArrayList([]const u8) {
    var ret = std.ArrayList([]const u8).init(&arena.allocator);
    if (zFindChild(root, tag)) |deps_node| {
        var it = ZChildIterator.init(deps_node);
        const stdout = std.io.getStdOut().writer();
        while (it.next()) |child_node| {
            const src_node = zFindChild(child_node, "src") orelse return error.NoSrcTag;
            const type_node = src_node.*.child orelse return error.NoSrcType;
            const type_str = try zGetString(type_node);

            var fifo = std.fifo.LinearFifo(u8, .{ .Dynamic = {} }).init(&arena.allocator);
            var json = std.json.writeStream(fifo.writer(), 4);
            json.whitespace = .{
                .indent = .{ .Space = 0 },
                .separator = false,
            };

            try json.beginObject();
            try json.objectField(type_str);

            if (std.mem.eql(u8, "pkg", type_str)) {
                try json.beginObject();

                try json.objectField("repository");
                try json.emitString((try zFindString(type_node, "repository")) orelse return error.NoRepository);

                try json.objectField("user");
                try json.emitString((try zFindString(type_node, "user")) orelse return error.NoUser);

                try json.objectField("name");
                try json.emitString((try zFindString(type_node, "name")) orelse return error.NoName);

                try json.objectField("version");
                try json.emitString((try zFindString(type_node, "version")) orelse return error.NoVersion);

                try json.endObject();
            } else if (std.mem.eql(u8, "github", type_str)) {
                try json.beginObject();

                try json.objectField("repo");
                try json.emitString((try zFindString(type_node, "repo")) orelse return error.NoRepo);

                try json.objectField("user");
                try json.emitString((try zFindString(type_node, "user")) orelse return error.NoUser);

                try json.objectField("ref");
                try json.emitString((try zFindString(type_node, "ref")) orelse return error.NoRef);

                try json.endObject();
            } else if (std.mem.eql(u8, "url", type_str)) {
                try json.emitString(try zGetString(type_node.*.child orelse return error.NoUrl));
            } else return error.InvalidTag;

            try json.endObject();

            // have to do replacement because the stream writer doesn't minify correctly
            try ret.append(try std.mem.replaceOwned(u8, &arena.allocator, fifo.readableSlice(0), "\n", ""));
        }
    }

    return ret;
}

pub fn main() !void {
    var args = std.process.args();
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = &arena.allocator;
    _ = args.nextPosix();
    const username = args.nextPosix() orelse return error.NoUsername;
    const path = args.nextPosix() orelse return error.NoPath;

    var client: redis.Client = undefined;
    try client.init(try std.net.connectUnixSocket("/var/run/redis/redis.sock"));
    defer client.close();

    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var gzip = try std.compress.gzip.gzipStream(allocator, file.reader());
    defer gzip.deinit();

    var extractor = tar.fileExtractor("manifest.zzz", gzip.reader());
    const text = try extractor.reader().readAllAlloc(allocator, std.math.maxInt(usize));

    var tree = zzz.ZTree(1, 1000){};
    var root = try tree.appendText(text);
    const deps = try serializeDepsToJson(&arena, root, "deps");
    const build_deps = try serializeDepsToJson(&arena, root, "build_deps");
    var tags = std.ArrayList([]const u8).init(allocator);
    if (zFindChild(root, "tags")) |tags_node| {
        var it = ZChildIterator.init(tags_node);
        while (it.next()) |tag_node| try tags.append(try zGetString(tag_node));
    }

    // required fields
    const name = (try zFindString(root, "name")) orelse return error.NoName;
    const semver_str = (try zFindString(root, "version")) orelse return error.NoVersion;
    const semver = try version.Semver.parse(semver_str);

    // check if it exists
    const versions_key = try std.fmt.allocPrint(allocator, "user:{s}:pkg:{s}", .{
        username, name,
    });

    if ((try client.send(usize, SISMEMBER.init(versions_key, semver_str))) > 0) {
        std.log.err("'{s}/{s}' {} is already published", .{ username, name, semver });
        return error.AlreadyPublished;
    }

    // is it the latest?
    const latest_key = try std.fmt.allocPrint(allocator, "{s}:latest", .{versions_key});
    const latest_str: ?FixBuf(5) = switch (try client.send(OrErr(FixBuf(5)), GET.init(latest_key))) {
        .Ok => |val| val,
        .Nil => null,
        .Err => return error.Redis,
    };

    const publishing_latest = if (latest_str) |str| switch (semver.cmp(try version.Semver.parse(str.toSlice()))) {
        .lt => false,
        .gt => true,
        .eq => {
            std.log.err("'{s}/{s}' {} is already published", .{ username, name, semver });
            return error.AlreadyPublished;
        },
    } else true;

    var fields = std.ArrayList(FV).init(allocator);
    inline for (optional_fields) |field| {
        if (try zFindString(root, field)) |value| try fields.append(.{ .field = field, .value = value });
    }

    try fields.append(.{ .field = "downloads", .value = "0" });

    const current_key = try std.fmt.allocPrint(allocator, "{s}:{}", .{
        versions_key, semver,
    });
    const keys = .{
        .pkg = current_key,
        .versions = versions_key,
        .tags = try std.fmt.allocPrint(allocator, "{s}:tags", .{current_key}),
        .deps = try std.fmt.allocPrint(allocator, "{s}:deps", .{current_key}),
        .build_deps = try std.fmt.allocPrint(allocator, "{s}:build_deps", .{
            current_key,
        }),
    };

    // TODO: do proper cleanup on error
    const reply = try client.trans(struct {
        pkg: OrErr(void),
        versions: OrErr(void),
    }, .{
        HSET.init(keys.pkg, fields.items),
        SADD.init(keys.versions, &[_][]const u8{semver_str}),
    });
    errdefer {
        inline for (std.meta.fields(@TypeOf(reply))) |field| {
            if (@field(reply, field.name) == .Ok) {
                std.log.debug("removing {s}", .{field.name});
                client.send(void, .{ "DEL", @field(keys, field.name) }) catch {};
            }
        }
    }

    inline for (std.meta.fields(@TypeOf(reply))) |field| {
        if (@field(reply, field.name) != .Ok) {
            std.log.err("issue with {s}", .{field.name});

            return error.Redis;
        }
    }

    if (tags.items.len > 0)
        try client.send(void, SADD.init(keys.tags, tags.items));
    errdefer client.send(void, .{ "DEL", keys.tags }) catch {};

    if (deps.items.len > 0)
        try client.send(void, SADD.init(keys.deps, deps.items));
    errdefer client.send(void, .{ "DEL", keys.deps }) catch {};

    if (build_deps.items.len > 0)
        try client.send(void, SADD.init(keys.build_deps, build_deps.items));
    errdefer client.send(void, .{ "DEL", keys.build_deps }) catch {};

    var old_version: ?FixBuf(5) = if (publishing_latest) blk: {
        const ret: ?FixBuf(5) = switch (try client.send(OrErr(FixBuf(5)), GET.init(latest_key))) {
            .Ok => |val| val,
            .Nil => null,
            .Err => return error.OldLatest,
        };
        try client.send(void, SET.init(latest_key, semver_str, .NoExpire, .NoConditions));
        break :blk ret;
    } else null;
    errdefer if (publishing_latest) {
        if (old_version) |ver|
            client.send(void, SET.init(latest_key, ver.toSlice(), .NoExpire, .NoConditions)) catch {}
        else
            client.send(void, .{ "DEL", latest_key }) catch {};
    };

    const package_id = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ username, name });
    for (tags.items) |tag| {
        const tag_key = try std.fmt.allocPrint(allocator, "tag:{s}", .{tag});
        try client.send(void, SADD.init(tag_key, &[_][]const u8{package_id}));
    }

    // TODO: rollback
    try client.send(void, SADD.init("pkgs", &[_][]const u8{package_id}));

    const user_pkgs_key = try std.fmt.allocPrint(allocator, "user:{s}:pkgs", .{username});
    try client.send(void, SADD.init(user_pkgs_key, &[_][]const u8{name}));

    // move file
    const user_path = try std.fs.path.join(allocator, &[_][]const u8{ "/var/www/archive", username });
    var user_dir = try std.fs.openDirAbsolute(user_path, .{});
    defer user_dir.close();

    var dst_dir = try user_dir.makeOpenPath(try std.fs.path.join(allocator, &[_][]const u8{ user_path, name }), .{});
    defer dst_dir.close();

    try std.fs.cwd().copyFile(path, dst_dir, semver_str, .{});
    std.log.info("published {s} {}", .{ package_id, semver });
}
