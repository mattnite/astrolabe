const std = @import("std");
const builtin = @import("builtin");
const http = @import("apple_pie");
const redis = @import("okredis");
const version = @import("version");
const tar = @import("tar");
const fs = http.FileServer;

const SISMEMBER = redis.commands.sets.SISMEMBER;
const SET = redis.commands.strings.SET;
const GET = redis.commands.strings.GET;
const FixBuf = redis.types.FixBuf;
const SSCAN = redis.commands.sets.SSCAN;
const HMGET = redis.commands.hashes.HMGET;
const OrErr = redis.types.OrErr;
const freeReply = redis.freeReply;
const router = http.router;
const os = std.os;
const archive_path = "/var/www/archive";

pub const io_mode = .evented;

var gpa = if (builtin.mode == .Debug)
    std.heap.GeneralPurposeAllocator(.{}){}
else
    undefined;

const allocator = if (builtin.mode == .Debug)
    &gpa.allocator
else
    std.heap.c_allocator;

const interrupt = os.Sigaction{
    .handler = .{ .sigaction = interruptFn },
    .mask = os.empty_sigset,
    .flags = os.SA_SIGINFO | os.SA_RESETHAND,
};

fn interruptFn(sig: i32, info: *const os.siginfo_t, ctx_ptr: ?*const c_void) callconv(.C) void {
    if (sig == std.c.SIGINT) {
        if (builtin.mode == .Debug) {
            _ = gpa.deinit();
        }
        std.process.exit(0);
    }
}

pub fn main() !void {
    defer if (builtin.mode == .Debug) {
        _ = gpa.deinit();
    };

    os.sigaction(std.c.SIGINT, &interrupt, null);

    try fs.init(allocator, .{ .dir_path = archive_path, .base_path = "archive" });
    defer fs.deinit();

    @setEvalBranchQuota(2000);
    try http.listenAndServe(
        allocator,
        try std.net.Address.parseIp("127.0.0.1", 8080),
        comptime router.router(&[_]router.Route{
            router.get("/pkgs", index), // return all latest packages
            router.get("/pkgs/:user", userPkgs), // return all latest packages for a user
            router.get("/pkgs/:user/:pkg", versions),
            router.get("/pkgs/:user/:pkg/latest", latest),
            router.get("/pkgs/:user/:pkg/:version", pkgInfo),
            router.get("/tags/:tag", tagPkgs), // return all latest packages for a tag
            router.get("/trees/:user/:pkg/:version", trees),
            router.get("/archive/:user/:pkg/:version", archive),
        }),
    );
}

fn getLatest(client: *redis.Client, user: []const u8, pkg: []const u8) !version.Semver {
    const key = try std.fmt.allocPrint(allocator, "user:{s}:pkg:{s}:latest", .{ user, pkg });
    defer allocator.free(key);

    const version_buf = try client.send(FixBuf(5), .{ "GET", key });
    return try version.Semver.parse(version_buf.toSlice());
}

fn streamPkgToJson(
    client: *redis.Client,
    json: anytype,
    user: []const u8,
    pkg: []const u8,
) !void {
    const semver = try getLatest(client, user, pkg);
    const ver_str = try std.fmt.allocPrint(allocator, "{}", .{semver});
    defer allocator.free(ver_str);

    const key = try std.fmt.allocPrint(allocator, "user:{s}:pkg:{s}:{}", .{
        user,
        pkg,
        semver,
    });
    defer allocator.free(key);

    const tags_key = try std.fmt.allocPrint(allocator, "{s}:tags", .{key});
    defer allocator.free(tags_key);

    const deps_key = try std.fmt.allocPrint(allocator, "{s}:deps", .{key});
    defer allocator.free(deps_key);

    const build_deps_key = try std.fmt.allocPrint(allocator, "{s}:build_deps", .{key});
    defer allocator.free(build_deps_key);

    const metadata = try client.sendAlloc(PkgMetadata, allocator, HMGET.forStruct(PkgMetadata).init(key));
    defer freeReply(metadata, allocator);

    try json.beginObject();

    try json.objectField("user");
    try json.emitString(user);

    try json.objectField("pkg");
    try json.emitString(pkg);

    try json.objectField("version");
    try json.emitString(ver_str);

    inline for (std.meta.fields(PkgMetadata)) |field| {
        switch (field.field_type) {
            u64 => {
                try json.objectField(field.name);
                try json.emitNumber(@field(metadata, field.name));
            },
            ?[]const u8 => {
                if (@field(metadata, field.name)) |value| {
                    try json.objectField(field.name);
                    try json.emitString(value);
                }
            },
            else => |T| @compileError("didn't account for this type: " ++ @typeName(T)),
        }
    }

    const tags = try client.sendAlloc([][]const u8, allocator, .{ "SMEMBERS", tags_key });
    defer freeReply(tags, allocator);

    const deps = try client.sendAlloc([][]const u8, allocator, .{ "SMEMBERS", deps_key });
    defer freeReply(deps, allocator);

    const build_deps = try client.sendAlloc([][]const u8, allocator, .{ "SMEMBERS", build_deps_key });
    defer freeReply(build_deps, allocator);

    try json.objectField("tags");
    try json.beginArray();
    for (tags) |tag| {
        try json.arrayElem();
        try json.emitString(tag);
    }
    try json.endArray();

    var parser = std.json.Parser.init(allocator, false);
    defer parser.deinit();

    try json.objectField("deps");
    try json.beginArray();
    for (deps) |dep| {
        const value_tree = try parser.parse(dep);

        try json.arrayElem();
        try json.emitJson(value_tree.root);
        parser.reset();
    }
    try json.endArray();

    try json.objectField("build_deps");
    try json.beginArray();
    for (build_deps) |build_dep| {
        const value_tree = try parser.parse(build_dep);

        try json.arrayElem();
        try json.emitJson(value_tree.root);
        parser.reset();
    }
    try json.endArray();

    try json.endObject();
}

fn cachePkgs(client: *redis.Client) !void {
    const pkgs = try client.sendAlloc([][]const u8, allocator, .{ "SMEMBERS", "pkgs" });
    defer freeReply(pkgs, allocator);

    var fifo = std.fifo.LinearFifo(u8, .{ .Dynamic = {} }).init(allocator);
    defer fifo.deinit();

    var json = std.json.writeStream(fifo.writer(), 5);
    try json.beginArray();

    for (pkgs) |pkg| {
        try json.arrayElem();
        var it = std.mem.tokenize(pkg, "/");
        try streamPkgToJson(
            client,
            &json,
            it.next() orelse return error.NoUser,
            it.next() orelse return error.NoPkg,
        );
    }

    try json.endArray();

    try client.send(void, SET.init("pkgs_json", fifo.readableSlice(0), .{ .Seconds = 3600 }, .NoConditions));
}

fn index(resp: *http.Response, req: http.Request) !void {
    var client: redis.Client = undefined;
    try client.init(try std.net.connectUnixSocket("/var/run/redis/redis.sock"));
    defer client.close();

    // first try to get cached value
    const reply: ?[]const u8 = switch (try client.sendAlloc(OrErr([]const u8), allocator, .{ "GET", "pkgs_json" })) {
        .Ok => |val| val,
        .Nil => blk: {
            try cachePkgs(&client);
            break :blk null;
        },
        .Err => {
            try resp.notFound();
            return error.Redis;
        },
    };

    const json = reply orelse client.sendAlloc([]const u8, allocator, .{ "GET", "pkgs_json" }) catch {
        std.log.err("failed to get cached json", .{});
        try resp.notFound();
        return;
    };
    defer freeReply(json, allocator);

    try resp.headers.put("Content-Type", "application/json");
    try resp.writer().writeAll(json);
}

fn versions(resp: *http.Response, req: http.Request, args: struct {
    user: []const u8,
    pkg: []const u8,
}) !void {
    var client: redis.Client = undefined;
    try client.init(try std.net.connectUnixSocket("/var/run/redis/redis.sock"));
    defer client.close();

    const key = try std.fmt.allocPrint(allocator, "user:{s}:pkg:{s}", .{
        args.user,
        args.pkg,
    });
    defer allocator.free(key);

    const vers = try client.sendAlloc([][]const u8, allocator, .{ "SMEMBERS", key });
    defer freeReply(vers, allocator);

    if (vers.len == 0) {
        try resp.notFound();
        return;
    }

    var json = std.json.writeStream(resp.writer(), 4);
    try json.beginArray();
    for (vers) |ver| {
        try json.arrayElem();
        try json.emitString(ver);
    }
    try json.endArray();
}

fn userPkgs(resp: *http.Response, req: http.Request, user: []const u8) !void {
    const key = try std.fmt.allocPrint(allocator, "user:{s}:pkgs", .{user});
    defer allocator.free(key);

    var client: redis.Client = undefined;
    try client.init(try std.net.connectUnixSocket("/var/run/redis/redis.sock"));
    defer client.close();

    const exists = try client.send(u1, .{ "EXISTS", key[0 .. key.len - 5] });
    if (exists == 0) {
        try resp.notFound();
        return;
    }

    const pkgs = try client.sendAlloc([][]const u8, allocator, .{ "SMEMBERS", key });
    defer freeReply(pkgs, allocator);

    try resp.headers.put("Content-Type", "application/json");
    var json = std.json.writeStream(resp.writer(), 5);
    try json.beginArray();

    for (pkgs) |pkg| {
        try json.arrayElem();
        try streamPkgToJson(&client, &json, user, pkg);
    }

    try json.endArray();
}

fn tagPkgs(resp: *http.Response, req: http.Request, tag: []const u8) !void {
    const key = try std.fmt.allocPrint(allocator, "tag:{s}", .{tag});
    defer allocator.free(key);

    var client: redis.Client = undefined;
    try client.init(try std.net.connectUnixSocket("/var/run/redis/redis.sock"));
    defer client.close();

    const exists = try client.send(u1, .{ "EXISTS", key });
    if (exists == 0) {
        try resp.notFound();
        return;
    }

    const pkgs = try client.sendAlloc([][]const u8, allocator, .{ "SMEMBERS", key });
    defer freeReply(pkgs, allocator);

    try resp.headers.put("Content-Type", "application/json");
    var json = std.json.writeStream(resp.writer(), 5);
    try json.beginArray();

    for (pkgs) |pkg| {
        try json.arrayElem();
        var it = std.mem.tokenize(pkg, "/");
        try streamPkgToJson(
            &client,
            &json,
            it.next() orelse return error.NoUser,
            it.next() orelse return error.NoPkg,
        );
    }

    try json.endArray();
}

// get the latest version of a package
fn latest(resp: *http.Response, req: http.Request, args: struct {
    user: []const u8,
    pkg: []const u8,
}) !void {
    var client: redis.Client = undefined;
    try client.init(try std.net.connectUnixSocket("/var/run/redis/redis.sock"));
    defer client.close();

    var query = try req.url.queryParameters(allocator);
    defer query.deinit();

    if (query.get("v")) |range_str| {
        const range = try version.Range.parse(range_str);
        const key = try std.fmt.allocPrint(allocator, "user:{s}:pkg:{s}", .{
            args.user,
            args.pkg,
        });
        defer allocator.free(key);

        const vers = try client.sendAlloc([][]const u8, allocator, .{ "SMEMBERS", key });
        defer freeReply(vers, allocator);

        var semver: ?version.Semver = null;
        for (vers) |ver_str| {
            const new_semver = version.Semver.parse(ver_str) catch |err| {
                continue;
            };

            if (!range.contains(new_semver)) continue;
            semver = if (semver) |ver|
                if (new_semver.cmp(ver) == .gt) new_semver else semver
            else
                new_semver;
        }

        if (semver) |ver| {
            try resp.writer().print("{}", .{ver});
        } else {
            try resp.notFound();
        }
    } else {
        try resp.writer().print("{}", .{try getLatest(&client, args.user, args.pkg)});
    }
}

const PkgMetadata = struct {
    description: ?[]const u8,
    license: ?[]const u8,
    source_url: ?[]const u8,
    homepage_url: ?[]const u8,
    downloads: u64,
};

// get all the info of a package
fn pkgInfo(resp: *http.Response, req: http.Request, args: struct {
    user: []const u8,
    pkg: []const u8,
    version: []const u8,
}) !void {
    // validate version string
    _ = version.Semver.parse(args.version) catch {
        try resp.notFound();
        return;
    };

    const key = try std.fmt.allocPrint(allocator, "user:{s}:pkg:{s}:{s}", .{
        args.user,
        args.pkg,
        args.version,
    });
    defer allocator.free(key);

    const tags_key = try std.fmt.allocPrint(allocator, "{s}:tags", .{key});
    defer allocator.free(tags_key);

    const deps_key = try std.fmt.allocPrint(allocator, "{s}:deps", .{key});
    defer allocator.free(deps_key);

    const build_deps_key = try std.fmt.allocPrint(allocator, "{s}:build_deps", .{key});
    defer allocator.free(build_deps_key);

    var client: redis.Client = undefined;
    try client.init(try std.net.connectUnixSocket("/var/run/redis/redis.sock"));
    defer client.close();

    const reply = client.sendAlloc(OrErr(PkgMetadata), allocator, HMGET.forStruct(PkgMetadata).init(key)) catch {
        try resp.notFound();
        return;
    };
    defer freeReply(reply, allocator);

    const metadata = switch (reply) {
        .Err, .Nil => {
            try resp.notFound();
            return;
        },
        .Ok => |val| val,
    };

    var json = std.json.writeStream(resp.writer(), 4);
    try json.beginObject();

    inline for (std.meta.fields(@TypeOf(args))) |field| {
        try json.objectField(field.name);
        try json.emitString(@field(args, field.name));
    }

    inline for (std.meta.fields(PkgMetadata)) |field| {
        switch (field.field_type) {
            u64 => {
                try json.objectField(field.name);
                try json.emitNumber(@field(metadata, field.name));
            },
            ?[]const u8 => {
                if (@field(metadata, field.name)) |value| {
                    try json.objectField(field.name);
                    try json.emitString(value);
                }
            },
            else => |T| @compileError("didn't account for this type: " ++ @typeName(T)),
        }
    }

    const tags = try client.sendAlloc([][]const u8, allocator, .{ "SMEMBERS", tags_key });
    defer freeReply(tags, allocator);

    const deps = try client.sendAlloc([][]const u8, allocator, .{ "SMEMBERS", deps_key });
    defer freeReply(deps, allocator);

    const build_deps = try client.sendAlloc([][]const u8, allocator, .{ "SMEMBERS", build_deps_key });
    defer freeReply(build_deps, allocator);

    try json.objectField("tags");
    try json.beginArray();
    for (tags) |tag| {
        try json.arrayElem();
        try json.emitString(tag);
    }
    try json.endArray();

    var parser = std.json.Parser.init(allocator, false);
    defer parser.deinit();

    try json.objectField("deps");
    try json.beginArray();
    for (deps) |dep| {
        const value_tree = try parser.parse(dep);

        try json.arrayElem();
        try json.emitJson(value_tree.root);
        parser.reset();
    }
    try json.endArray();

    try json.objectField("build_deps");
    try json.beginArray();
    for (build_deps) |build_dep| {
        const value_tree = try parser.parse(build_dep);

        try json.arrayElem();
        try json.emitJson(value_tree.root);
        parser.reset();
    }
    try json.endArray();

    try json.endObject();
}

fn trees(resp: *http.Response, req: http.Request, args: struct {
    user: []const u8,
    pkg: []const u8,
    version: []const u8,
}) !void {
    var query = try req.url.queryParameters(allocator);
    defer query.deinit();

    const subpath = try std.fs.path.join(allocator, &[_][]const u8{
        "pkg", query.get("path") orelse {
            try resp.notFound();
            return;
        },
    });

    const semver = try version.Semver.parse(args.version);
    const path = try std.fs.path.join(
        allocator,
        &[_][]const u8{ archive_path, args.user, args.pkg, args.version },
    );
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{ .read = true }) catch |err| {
        if (err == error.FileNotFound) {
            try resp.notFound();
            return;
        } else return err;
    };
    defer file.close();

    var gzip = try std.compress.gzip.gzipStream(allocator, file.reader());
    defer gzip.deinit();

    var extractor = tar.fileExtractor(subpath, gzip.reader());
    var fifo = std.fifo.LinearFifo(u8, .{ .Static = std.mem.page_size }).init();

    // set headers
    try resp.headers.put("Access-Control-Allow-Origin", "*");
    fifo.pump(extractor.reader(), resp.writer()) catch |err| {
        if (err == error.FileNotFound)
            try resp.notFound()
        else
            return err;
    };
}

fn archive(resp: *http.Response, req: http.Request, args: struct {
    user: []const u8,
    pkg: []const u8,
    version: []const u8,
}) !void {
    // validate version string
    _ = version.Semver.parse(args.version) catch {
        try resp.notFound();
        return;
    };

    var client: redis.Client = undefined;
    try client.init(try std.net.connectUnixSocket("/var/run/redis/redis.sock"));
    defer client.close();

    const key = try std.fmt.allocPrint(allocator, "user:{s}:pkg:{s}:{s}", .{ args.user, args.pkg, args.version });
    defer allocator.free(key);

    // make sure package exists
    const versions_key = key[0 .. key.len - 6];
    if ((try client.send(usize, SISMEMBER.init(versions_key, args.version))) == 0) {
        try resp.notFound();
        return;
    }

    try fs.serve(resp, req);
    try client.send(void, .{ "HINCRBY", key, "downloads", 1 });
}
