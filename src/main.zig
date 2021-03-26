const std = @import("std");
const builtin = @import("builtin");

const http = @import("apple_pie");
const redis = @import("okredis");
const tar = @import("tar");
const version = @import("version");
const zzz = @import("zzz");

usingnamespace @import("common.zig");

const FV = redis.commands.hashes.utils.FV;
const FixBuf = redis.types.FixBuf;
const GET = redis.commands.strings.GET;
const HMGET = redis.commands.hashes.HMGET;
const HSET = redis.commands.hashes.HSET;
const OrErr = redis.types.OrErr;
const SADD = redis.commands.sets.SADD;
const SET = redis.commands.strings.SET;
const SISMEMBER = redis.commands.sets.SISMEMBER;
const freeReply = redis.freeReply;

const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const fs = http.FileServer;
const os = std.os;
const router = http.router;

const archive_path = "/var/www/archive";
pub const io_mode = .evented;

var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{
    .stack_trace_frames = 20,
}){};
const gpa = &general_purpose_allocator.allocator;

var server = http.Server.init();

const interrupt = os.Sigaction{
    .handler = .{ .sigaction = interruptFn },
    .mask = os.empty_sigset,
    .flags = os.SA_SIGINFO | os.SA_RESETHAND,
};

fn interruptFn(sig: i32, info: *const os.siginfo_t, ctx_ptr: ?*const c_void) callconv(.C) void {
    if (sig == std.c.SIGINT) {
        server.shutdown();
        _ = general_purpose_allocator.deinit();
        std.process.exit(0);
    }
}

const optional_fields = [_][]const u8{
    "description",
    "homepage_url",
    "source_url",
    "license",
};

pub fn main() !void {
    defer _ = general_purpose_allocator.deinit();

    try fs.init(gpa, .{ .dir_path = archive_path, .base_path = "archive" });
    defer fs.deinit();

    os.sigaction(std.c.SIGINT, &interrupt, null);
    @setEvalBranchQuota(2000);
    try server.run(
        gpa,
        try std.net.Address.parseIp("127.0.0.1", 42069),
        comptime router.router(&[_]router.Route{
            router.get("/pkgs", index), // return all latest packages
            router.get("/pkgs/:user", userPkgs), // return all latest packages for a user
            router.get("/pkgs/:user/:pkg", versions),
            router.get("/pkgs/:user/:pkg/latest", latest),
            router.get("/pkgs/:user/:pkg/:version", pkgInfo),
            router.get("/tags/:tag", tagPkgs), // return all latest packages for a tag
            router.get("/trees/:user/:pkg/:version", trees),
            router.get("/archive/:user/:pkg/:version", archive),

            router.post("/publish", publish),
        }),
    );
}

fn getLatest(client: *redis.Client, user: []const u8, pkg: []const u8) !version.Semver {
    const key = try std.fmt.allocPrint(gpa, "user:{s}:pkg:{s}:latest", .{ user, pkg });
    defer gpa.free(key);

    const version_buf = try client.send(FixBuf(80), .{ "GET", key });
    return try version.Semver.parse(version_buf.toSlice());
}

fn streamPkgToJson(
    client: *redis.Client,
    arena: *ArenaAllocator,
    json: anytype,
    user: []const u8,
    pkg: []const u8,
) !void {
    const allocator = &arena.allocator;
    const semver = try getLatest(client, user, pkg);
    const ver_str = try std.fmt.allocPrint(allocator, "{}", .{semver});
    const key = try std.fmt.allocPrint(allocator, "user:{s}:pkg:{s}:{}", .{
        user,
        pkg,
        semver,
    });

    const tags_key = try std.fmt.allocPrint(allocator, "{s}:tags", .{key});
    const deps_key = try std.fmt.allocPrint(allocator, "{s}:deps", .{key});
    const build_deps_key = try std.fmt.allocPrint(allocator, "{s}:build_deps", .{key});
    const metadata = try client.sendAlloc(PkgMetadata, allocator, HMGET.forStruct(PkgMetadata).init(key));

    try json.beginObject();

    try json.objectField("user");
    try json.emitString(user);

    try json.objectField("name");
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
    const deps = try client.sendAlloc([][]const u8, allocator, .{ "SMEMBERS", deps_key });
    const build_deps = try client.sendAlloc([][]const u8, allocator, .{ "SMEMBERS", build_deps_key });

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

fn cachePkgs(client: *redis.Client, arena: *ArenaAllocator) !void {
    const allocator = &arena.allocator;
    const pkgs = try client.sendAlloc([][]const u8, allocator, .{ "SMEMBERS", "pkgs" });
    var fifo = std.fifo.LinearFifo(u8, .{ .Dynamic = {} }).init(allocator);
    defer fifo.deinit();

    var json = std.json.writeStream(fifo.writer(), 5);
    try json.beginArray();

    for (pkgs) |pkg| {
        try json.arrayElem();
        var it = std.mem.tokenize(pkg, "/");
        try streamPkgToJson(
            client,
            arena,
            &json,
            it.next() orelse return error.NoUser,
            it.next() orelse return error.NoPkg,
        );
    }

    try json.endArray();

    try client.send(void, SET.init("pkgs_json", fifo.readableSlice(0), .{ .Seconds = 3600 }, .NoConditions));
}

fn index(resp: *http.Response, req: http.Request) !void {
    var arena = ArenaAllocator.init(gpa);
    defer arena.deinit();

    const allocator = &arena.allocator;
    var client: redis.Client = undefined;
    try client.init(try std.net.connectUnixSocket("/var/run/redis/redis.sock"));
    defer client.close();

    // first try to get cached value
    const reply: ?[]const u8 = switch (try client.sendAlloc(OrErr([]const u8), allocator, .{ "GET", "pkgs_json" })) {
        .Ok => |val| val,
        .Nil => blk: {
            try cachePkgs(&client, &arena);
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

    try resp.headers.put("Content-Type", "application/json");
    try resp.headers.put("Access-Control-Allow-Origin", "*");
    try resp.writer().writeAll(json);
}

fn versions(resp: *http.Response, req: http.Request, args: struct {
    user: []const u8,
    pkg: []const u8,
}) !void {
    var arena = ArenaAllocator.init(gpa);
    defer arena.deinit();

    const allocator = &arena.allocator;
    var client: redis.Client = undefined;
    try client.init(try std.net.connectUnixSocket("/var/run/redis/redis.sock"));
    defer client.close();

    const key = try std.fmt.allocPrint(allocator, "user:{s}:pkg:{s}", .{
        args.user,
        args.pkg,
    });

    const vers = try client.sendAlloc([][]const u8, allocator, .{ "SMEMBERS", key });
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

    try resp.headers.put("Content-Type", "application/json");
    try resp.headers.put("Access-Control-Allow-Origin", "*");
}

fn userPkgs(resp: *http.Response, req: http.Request, user: []const u8) !void {
    var arena = ArenaAllocator.init(gpa);
    defer arena.deinit();

    const allocator = &arena.allocator;
    const key = try std.fmt.allocPrint(allocator, "user:{s}:pkgs", .{user});
    var client: redis.Client = undefined;
    try client.init(try std.net.connectUnixSocket("/var/run/redis/redis.sock"));
    defer client.close();

    const exists = try client.send(u1, .{ "EXISTS", key[0 .. key.len - 5] });
    if (exists == 0) {
        try resp.notFound();
        return;
    }

    const pkgs = try client.sendAlloc([][]const u8, allocator, .{ "SMEMBERS", key });
    try resp.headers.put("Content-Type", "application/json");
    try resp.headers.put("Access-Control-Allow-Origin", "*");
    var json = std.json.writeStream(resp.writer(), 5);
    try json.beginArray();

    for (pkgs) |pkg| {
        try json.arrayElem();
        try streamPkgToJson(&client, &arena, &json, user, pkg);
    }

    try json.endArray();
}

fn tagPkgs(resp: *http.Response, req: http.Request, tag: []const u8) !void {
    var arena = ArenaAllocator.init(gpa);
    defer arena.deinit();

    const allocator = &arena.allocator;
    const key = try std.fmt.allocPrint(allocator, "tag:{s}", .{tag});
    var client: redis.Client = undefined;
    try client.init(try std.net.connectUnixSocket("/var/run/redis/redis.sock"));
    defer client.close();

    const exists = try client.send(u1, .{ "EXISTS", key });
    if (exists == 0) {
        try resp.notFound();
        return;
    }

    const pkgs = try client.sendAlloc([][]const u8, allocator, .{ "SMEMBERS", key });
    try resp.headers.put("Content-Type", "application/json");
    try resp.headers.put("Access-Control-Allow-Origin", "*");
    var json = std.json.writeStream(resp.writer(), 5);
    try json.beginArray();

    for (pkgs) |pkg| {
        try json.arrayElem();
        var it = std.mem.tokenize(pkg, "/");
        try streamPkgToJson(
            &client,
            &arena,
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

    var query = try req.url.queryParameters(gpa);
    defer query.deinit();

    if (query.get("v")) |range_str| {
        const range = try version.Range.parse(range_str);
        const key = try std.fmt.allocPrint(gpa, "user:{s}:pkg:{s}", .{
            args.user,
            args.pkg,
        });
        defer gpa.free(key);

        const vers = try client.sendAlloc([][]const u8, gpa, .{ "SMEMBERS", key });
        defer freeReply(vers, gpa);

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

    try resp.headers.put("Access-Control-Allow-Origin", "*");
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
    var arena = ArenaAllocator.init(gpa);
    defer arena.deinit();

    const allocator = &arena.allocator;
    // validate version string
    _ = version.Semver.parse(args.version) catch {
        try resp.notFound();
        return;
    };

    var client: redis.Client = undefined;
    try client.init(try std.net.connectUnixSocket("/var/run/redis/redis.sock"));
    defer client.close();

    const key = try std.fmt.allocPrint(allocator, "user:{s}:pkg:{s}:{s}", .{
        args.user,
        args.pkg,
        args.version,
    });

    const tags_key = try std.fmt.allocPrint(allocator, "{s}:tags", .{key});
    const deps_key = try std.fmt.allocPrint(allocator, "{s}:deps", .{key});
    const build_deps_key = try std.fmt.allocPrint(allocator, "{s}:build_deps", .{key});
    const reply = client.sendAlloc(OrErr(PkgMetadata), allocator, HMGET.forStruct(PkgMetadata).init(key)) catch {
        try resp.notFound();
        return;
    };

    const metadata = switch (reply) {
        .Err, .Nil => {
            try resp.notFound();
            return;
        },
        .Ok => |val| val,
    };

    var json = std.json.writeStream(resp.writer(), 4);
    try json.beginObject();

    try json.objectField("user");
    try json.emitString(args.user);

    try json.objectField("name");
    try json.emitString(args.pkg);

    try json.objectField("version");
    try json.emitString(args.version);

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
    const deps = try client.sendAlloc([][]const u8, allocator, .{ "SMEMBERS", deps_key });
    const build_deps = try client.sendAlloc([][]const u8, allocator, .{ "SMEMBERS", build_deps_key });
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
        var value_tree = try parser.parse(dep);
        defer value_tree.deinit();

        try json.arrayElem();
        try json.emitJson(value_tree.root);
        parser.reset();
    }
    try json.endArray();

    try json.objectField("build_deps");
    try json.beginArray();
    for (build_deps) |build_dep| {
        var value_tree = try parser.parse(build_dep);
        defer value_tree.deinit();

        try json.arrayElem();
        try json.emitJson(value_tree.root);
        parser.reset();
    }
    try json.endArray();

    try json.endObject();

    try resp.headers.put("Content-Type", "application/json");
    try resp.headers.put("Access-Control-Allow-Origin", "*");
}

fn trees(resp: *http.Response, req: http.Request, args: struct {
    user: []const u8,
    pkg: []const u8,
    version: []const u8,
}) !void {
    var arena = ArenaAllocator.init(gpa);
    defer arena.deinit();

    const allocator = &arena.allocator;
    var query = try req.url.queryParameters(allocator);
    defer query.deinit();

    const subpath = try std.fs.path.join(allocator, &.{
        "pkg", query.get("path") orelse {
            try resp.notFound();
            return;
        },
    });

    const semver = try version.Semver.parse(args.version);
    const path = try std.fs.path.join(
        allocator,
        &.{ archive_path, args.user, args.pkg, args.version },
    );

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

    const key = try std.fmt.allocPrint(gpa, "user:{s}:pkg:{s}:{s}", .{ args.user, args.pkg, args.version });
    defer gpa.free(key);

    // make sure package exists
    const versions_key = key[0 .. key.len - 6];
    if ((try client.send(usize, SISMEMBER.init(versions_key, args.version))) == 0) {
        try resp.notFound();
        return;
    }

    try fs.serve(resp, req);
    try client.send(void, .{ "HINCRBY", key, "downloads", 1 });
}

fn publish(resp: *http.Response, req: http.Request) !void {
    var arena = ArenaAllocator.init(gpa);
    defer arena.deinit();

    const allocator = &arena.allocator;
    var headers = try req.headers(allocator);
    const authorization = headers.get("Authorization") orelse return error.NoAuth;
    const id = headers.get("X-User-Id") orelse return error.NoId;
    const provider = headers.get("X-User-Provider") orelse return error.NoProvider;
    const username = headers.get("X-User-Username") orelse return error.NoUsername;
    const email = headers.get("X-User-Email") orelse return error.NoEmail;
    const length = headers.get("Content-Length") orelse return error.NoContentLength;
    if (!std.mem.eql(u8, provider, "github")) {
        resp.status_code = .service_unavailable;
        try resp.body.print("Unsupported provider: {s}", .{provider});
        return;
    }

    var client: redis.Client = undefined;
    try client.init(try std.net.connectUnixSocket("/var/run/redis/redis.sock"));
    defer client.close();

    createUser(&client, &arena, id, username, email) catch |err| switch (err) {
        error.Banned => {
            resp.status_code = .forbidden;
            try resp.body.writeAll("You are banned");
            return;
        },
        error.Taken => {
            resp.status_code = .forbidden;
            try resp.body.print("username '{s}' used to be used by a different github account", .{username});
            return;
        },
        else => return err,
    };

    // TODO: rate limiting
    if (1_000_000 < try std.fmt.parseInt(usize, length, 10)) {
        resp.status_code = .forbidden;
        try resp.body.writeAll("uncompressed package size is greater that 1 million bytes");
        return;
    }

    var archive_dir = try std.fs.openDirAbsolute(archive_path, .{});
    defer archive_dir.close();

    var user_dir = try archive_dir.makeOpenPath(username, .{});
    defer user_dir.close();

    const text = blk: {
        var fixed_buffer = std.io.fixedBufferStream(req.body);
        var extractor = tar.fileExtractor("manifest.zzz", fixed_buffer.reader());
        break :blk try extractor.reader().readAllAlloc(allocator, std.math.maxInt(usize));
    };

    var tree = zzz.ZTree(1, 1000){};
    var root = try tree.appendText(text);
    const ver_str = (try zFindString(root, "version")) orelse return error.NoVersion;
    const name = (try zFindString(root, "name")) orelse return error.NoName;
    _ = version.Semver.parse(ver_str) catch {
        resp.status_code = .bad_request;
        try resp.body.print("Invalid version string: {s}", .{ver_str});
        return;
    };

    var dst_dir = try user_dir.makeOpenPath(name, .{});
    defer dst_dir.close();

    {
        // TODO: change to proper gzip compression
        const file = try dst_dir.createFile(try std.mem.join(allocator, "", &.{ ver_str, ".tar" }), .{});
        defer file.close();

        try file.writer().writeAll(req.body);
    }

    createPkg(&client, &arena, root, username, name, ver_str) catch |err| if (err == error.AlreadyPublished) {
        resp.status_code = .bad_request;
        try resp.body.print("Package already published: '{s}/{s}' {s}", .{ username, name, ver_str });
        return;
    } else return err;
    try client.send(void, .{ "DEL", "pkgs_json" });
    try resp.body.print("Package successfully published to https://astrolabe.pm/#/package/{s}/{s}/{s}", .{ username, name, ver_str });
}

fn createUser(
    client: *redis.Client,
    arena: *ArenaAllocator,
    id: []const u8,
    username: []const u8,
    email: []const u8,
) anyerror!void {
    const allocator = &arena.allocator;
    const keys = .{
        .id = try std.fmt.allocPrint(allocator, "github:{s}", .{id}),
        .user = try std.fmt.allocPrint(allocator, "user:{s}", .{username}),
    };

    // id value is the username
    const id_user: ?[]const u8 = client.sendAlloc([]const u8, allocator, GET.init(keys.id)) catch |err|
        if (err == error.GotNilReply)
        null
    else
        return err;

    // user id should be equal to id
    const user_id: ?[]const u8 = client.sendAlloc([]const u8, allocator, .{ "HGET", keys.user, "id" }) catch |err|
        if (err == error.GotNilReply)
        null
    else
        return err;

    // check if the user is banned, or check if the user is not registered to a different id
    if (user_id) |ui| {
        if (std.mem.eql(u8, ui, "banned"))
            return error.Banned;

        if (!std.mem.eql(u8, id, ui))
            return error.Taken;

        if (id_user != null)
            return;
    }

    try client.send(void, .{ "SET", keys.id, username });
    try client.send(void, HSET.init(keys.user, &[_]FV{
        .{ .field = "id", .value = id },
        .{ .field = "email", .value = email },
    }));

    const path = try std.fs.path.join(allocator, &.{ "/var/www/archive/", username });
    std.fs.makeDirAbsolute(path) catch |err| {
        if (err != error.PathAlreadyExists)
            return err;
    };

    std.log.info("added user '{s}'", .{username});
}

pub fn serializeDepsToJson(
    arena: *ArenaAllocator,
    root: *zzz.ZNode,
    tag: []const u8,
) !std.ArrayList([]const u8) {
    const allocator = &arena.allocator;
    var ret = std.ArrayList([]const u8).init(allocator);
    if (zFindChild(root, tag)) |deps_node| {
        var it = ZChildIterator.init(deps_node);
        const stdout = std.io.getStdOut().writer();
        while (it.next()) |child_node| {
            const src_node = zFindChild(child_node, "src") orelse return error.NoSrcTag;
            const type_node = src_node.*.child orelse return error.NoSrcType;
            const type_str = try zGetString(type_node);

            var fifo = std.fifo.LinearFifo(u8, .{ .Dynamic = {} }).init(allocator);
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
            try ret.append(try std.mem.replaceOwned(u8, allocator, fifo.readableSlice(0), "\n", ""));
        }
    }

    return ret;
}

pub fn createPkg(
    client: *redis.Client,
    arena: *ArenaAllocator,
    manifest: *zzz.ZNode,
    username: []const u8,
    name: []const u8,
    semver_str: []const u8,
) !void {
    const allocator = &arena.allocator;
    const deps = try serializeDepsToJson(arena, manifest, "deps");
    const build_deps = try serializeDepsToJson(arena, manifest, "build_deps");
    var tags = std.ArrayList([]const u8).init(allocator);
    if (zFindChild(manifest, "tags")) |tags_node| {
        var it = ZChildIterator.init(tags_node);
        while (it.next()) |tag_node| try tags.append(try zGetString(tag_node));
    }

    // required fields
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
    const latest_str: ?[]const u8 = switch (try client.sendAlloc(OrErr([]const u8), allocator, GET.init(latest_key))) {
        .Ok => |val| val,
        .Nil => null,
        .Err => return error.Redis,
    };

    const publishing_latest = if (latest_str) |str| switch (semver.cmp(try version.Semver.parse(str))) {
        .lt => false,
        .gt => true,
        .eq => {
            std.log.err("'{s}/{s}' {} is already published", .{ username, name, semver });
            return error.AlreadyPublished;
        },
    } else true;

    var fields = std.ArrayList(FV).init(allocator);
    inline for (optional_fields) |field| {
        if (try zFindString(manifest, field)) |value| try fields.append(.{ .field = field, .value = value });
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
        SADD.init(keys.versions, &.{semver_str}),
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

    var old_version: ?[]const u8 = if (publishing_latest) blk: {
        const ret: ?[]const u8 = switch (try client.sendAlloc(OrErr([]const u8), allocator, GET.init(latest_key))) {
            .Ok => |val| val,
            .Nil => null,
            .Err => return error.OldLatest,
        };
        try client.send(void, SET.init(latest_key, semver_str, .NoExpire, .NoConditions));
        break :blk ret;
    } else null;
    errdefer if (publishing_latest) {
        if (old_version) |ver|
            client.send(void, SET.init(latest_key, ver, .NoExpire, .NoConditions)) catch {}
        else
            client.send(void, .{ "DEL", latest_key }) catch {};
    };

    const package_id = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ username, name });
    for (tags.items) |tag| {
        const tag_key = try std.fmt.allocPrint(allocator, "tag:{s}", .{tag});
        try client.send(void, SADD.init(tag_key, &.{package_id}));
    }

    // TODO: rollback
    try client.send(void, SADD.init("pkgs", &.{package_id}));

    const user_pkgs_key = try std.fmt.allocPrint(allocator, "user:{s}:pkgs", .{username});
    try client.send(void, SADD.init(user_pkgs_key, &.{name}));
}
