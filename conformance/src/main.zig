//! FIDO2 conformance server — HTTP shell over httpz.
//!
//! Thin transport layer that wires the four conformance endpoints (server.zig)
//! to HTTP routes. All verification is performed by the Passcay library; this
//! file only generates challenges, parses request bodies, and serializes the
//! {status, errorMessage} envelope. Run with `zig build run` (port 8080).

const std = @import("std");
const httpz = @import("httpz");
const passcay = @import("passcay");
const srv = @import("server.zig");

const PORT = 8080;

// The in-memory store is not concurrency-hardened; the FIDO Conformance Tool
// drives ceremonies sequentially, which is the intended use.
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

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.page_allocator;

    var app = App{ .ctx = srv.Context.init(allocator), .io = init.io };
    defer app.ctx.deinit();

    var server = try httpz.Server(*App).init(init.io, allocator, .{ .address = .localhost(PORT) }, &app);
    defer server.deinit();
    defer server.stop();

    var router = try server.router(.{});
    router.post("/attestation/options", attestationOptions, .{});
    router.post("/attestation/result", attestationResult, .{});
    router.post("/assertion/options", assertionOptions, .{});
    router.post("/assertion/result", assertionResult, .{});

    std.debug.print("FIDO2 conformance server listening on http://localhost:{d}/\n", .{PORT});
    try server.listen();
}
