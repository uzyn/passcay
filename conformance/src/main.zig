//! FIDO2 conformance server — HTTP shell over httpz.
//!
//! Thin transport layer that wires the four conformance endpoints (server.zig)
//! to HTTP routes. All verification is performed by the Passcay library; this
//! file generates challenges, parses request bodies, serializes the
//! {status, errorMessage} envelope, and optionally loads a FIDO metadata set.
//!
//! Flags:
//!   --metadata <dir>   load MDS3 metadata statements (*.json) as trust anchors
//!   --origin <url>     expected origin (default http://localhost:8080)
//!   --rp-id <id>       expected RP ID (default localhost)
//!   --port <n>         listen port (default 8080)
//!   --now <unix_secs>  pin certificate time validity (default: lenient).
//!                      Pass `--now $(date +%s)` for expired-certificate tests.

const std = @import("std");
const httpz = @import("httpz");
const passcay = @import("passcay");
const srv = @import("server.zig");

const App = struct {
    ctx: srv.Context,
    io: std.Io,

    fn challenge(self: *App, arena: std.mem.Allocator) ![]const u8 {
        return passcay.challenge.generate(self.io, arena);
    }

    fn write(_: *App, res: *httpz.Response, resp: srv.Response) void {
        res.status = resp.status;
        res.body = resp.body;
        res.header("content-type", "application/json");
    }
};

fn attestationOptions(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const ch = try app.challenge(res.arena);
    app.write(res, try srv.attestationOptions(&app.ctx, res.arena, req.body() orelse "{}", ch));
}

fn attestationResult(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    app.write(res, try srv.attestationResult(&app.ctx, res.arena, req.body() orelse "{}"));
}

fn assertionOptions(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const ch = try app.challenge(res.arena);
    app.write(res, try srv.assertionOptions(&app.ctx, res.arena, req.body() orelse "{}", ch));
}

fn assertionResult(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    app.write(res, try srv.assertionResult(&app.ctx, res.arena, req.body() orelse "{}"));
}

/// Load every *.json metadata statement in `dir_path` into MDS entries.
fn loadMetadata(io: std.Io, arena: std.mem.Allocator, dir_path: []const u8) ![]passcay.mds.Entry {
    var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true });
    defer dir.close(io);

    var entries = std.array_list.Managed(passcay.mds.Entry).init(arena);
    var it = dir.iterate();
    var skipped: usize = 0;
    while (try it.next(io)) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".json")) continue;
        const json = dir.readFileAlloc(io, entry.name, arena, .unlimited) catch {
            skipped += 1;
            continue;
        };
        const e = passcay.mds.parseStatement(arena, json) catch {
            skipped += 1;
            continue;
        };
        try entries.append(e);
    }
    if (skipped > 0) std.debug.print("metadata: skipped {d} non-statement file(s)\n", .{skipped});
    return entries.toOwnedSlice();
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    const arena = init.arena.allocator();

    var port: u16 = 8080;
    var origin: []const u8 = "http://localhost:8080";
    var rp_id: []const u8 = "localhost";
    var metadata_dir: ?[]const u8 = null;
    var now_sec: ?i64 = null;

    var args = init.minimal.args.iterate();
    _ = args.next(); // program name
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--metadata")) {
            metadata_dir = args.next();
        } else if (std.mem.eql(u8, a, "--origin")) {
            origin = args.next() orelse origin;
        } else if (std.mem.eql(u8, a, "--rp-id")) {
            rp_id = args.next() orelse rp_id;
        } else if (std.mem.eql(u8, a, "--port")) {
            if (args.next()) |p| port = std.fmt.parseInt(u16, p, 10) catch port;
        } else if (std.mem.eql(u8, a, "--now")) {
            if (args.next()) |n| now_sec = std.fmt.parseInt(i64, n, 10) catch null;
        }
    }

    var store: passcay.mds.Store = .{ .entries = &.{} };
    var store_ptr: ?*const passcay.mds.Store = null;
    if (metadata_dir) |dir_path| {
        store.entries = loadMetadata(io, arena, dir_path) catch |err| {
            std.debug.print("failed to load metadata from {s}: {s}\n", .{ dir_path, @errorName(err) });
            return err;
        };
        store_ptr = &store;
        // With a metadata store, enforce certificate time validity if a clock
        // was supplied (otherwise expired-certificate tests cannot be rejected).
        std.debug.print("loaded {d} metadata statement(s) from {s}\n", .{ store.entries.len, dir_path });
    }

    var app = App{ .ctx = srv.Context.init(gpa), .io = io };
    app.ctx.origin = origin;
    app.ctx.rp_id = rp_id;
    app.ctx.mds = store_ptr;
    app.ctx.now_sec = now_sec;
    defer app.ctx.deinit();

    var server = try httpz.Server(*App).init(io, gpa, .{ .address = .localhost(port) }, &app);
    defer server.deinit();
    defer server.stop();

    var router = try server.router(.{});
    router.post("/attestation/options", attestationOptions, .{});
    router.post("/attestation/result", attestationResult, .{});
    router.post("/assertion/options", assertionOptions, .{});
    router.post("/assertion/result", assertionResult, .{});

    std.debug.print("FIDO2 conformance server listening on http://localhost:{d}/ (origin={s}, rpId={s}, mds={s})\n", .{ port, origin, rp_id, if (store_ptr != null) "on" else "off" });
    try server.listen();
}
