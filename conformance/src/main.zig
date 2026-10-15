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
    verbose: bool = false,

    fn challenge(self: *App, arena: std.mem.Allocator) ![]const u8 {
        return passcay.challenge.generate(self.io, arena);
    }

    fn respond(self: *App, path: []const u8, req: *httpz.Request, res: *httpz.Response, resp: srv.Response) void {
        res.status = resp.status;
        res.body = resp.body;
        res.header("content-type", "application/json");
        if (self.verbose) {
            std.debug.print("{s} -> {d}\n  req: {s}\n  res: {s}\n", .{ path, resp.status, req.body() orelse "", resp.body });
        } else {
            std.debug.print("{s} -> {d} {s}\n", .{ path, resp.status, resp.body });
        }
    }
};

fn attestationOptions(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const ch = try app.challenge(res.arena);
    app.respond("POST /attestation/options", req, res, try srv.attestationOptions(&app.ctx, res.arena, req.body() orelse "{}", ch));
}

fn attestationResult(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    app.respond("POST /attestation/result", req, res, try srv.attestationResult(&app.ctx, res.arena, req.body() orelse "{}"));
}

fn assertionOptions(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const ch = try app.challenge(res.arena);
    app.respond("POST /assertion/options", req, res, try srv.assertionOptions(&app.ctx, res.arena, req.body() orelse "{}", ch));
}

fn assertionResult(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    app.respond("POST /assertion/result", req, res, try srv.assertionResult(&app.ctx, res.arena, req.body() orelse "{}"));
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

/// Fetch a URL over HTTP(S) and return the response body (allocated in `arena`).
fn fetchUrl(io: std.Io, gpa: std.mem.Allocator, arena: std.mem.Allocator, url: []const u8) ![]u8 {
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();
    var aw: std.Io.Writer.Allocating = .init(arena);
    const res = try client.fetch(.{ .location = .{ .url = url }, .response_writer = &aw.writer });
    if (@backingInt(res.status) != 200) return error.HttpStatusNotOk;
    return aw.written();
}

/// Whether any certificate in an MDS3 BLOB's JWS signing chain is revoked, per
/// the CRL named in that certificate's cRLDistributionPoints extension. The CRL
/// is fetched live and verified against its issuer; a revocation is honoured
/// unless the CRL signature is present, supported, and invalid (FIDO Metadata
/// Service BLOB processing — conformance MDS3 F-4 / F-5).
fn blobChainRevoked(io: std.Io, gpa: std.mem.Allocator, arena: std.mem.Allocator, blob: []const u8, root_der: []const u8) bool {
    var jws = passcay.jws.parse(arena, blob) catch return false;
    defer jws.deinit();
    const chain = jws.x5c;
    for (chain, 0..) |cert_der, k| {
        const url = passcay.x509.crl.distributionUrl(cert_der) orelse continue;
        const crl_der = fetchUrl(io, gpa, arena, url) catch {
            std.debug.print("  CRL fetch failed for {s}\n", .{url});
            continue;
        };
        const c = passcay.x509.crl.parse(crl_der) catch continue;
        const serial = passcay.x509.crl.serialNumber(cert_der) catch continue;
        if (!c.isRevoked(serial)) continue;
        // Revoked. Honour unless we can prove the CRL signature is invalid.
        const issuer_der = if (k + 1 < chain.len) chain[k + 1] else root_der;
        const issuer = passcay.x509.parse(issuer_der) catch return true;
        const valid = c.verifiedBy(issuer) catch return true; // unsupported alg → fail safe
        if (valid) return true;
    }
    return false;
}

/// Load a certificate file (PEM or DER) and return DER bytes (in `arena`).
fn loadRootCert(io: std.Io, arena: std.mem.Allocator, path: []const u8) ![]u8 {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .unlimited);
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    const begin = std.mem.indexOf(u8, bytes, begin_marker) orelse return bytes; // already DER
    const start = begin + begin_marker.len;
    const end = std.mem.indexOfPos(u8, bytes, start, end_marker) orelse return error.InvalidPem;

    var clean = std.array_list.Managed(u8).init(arena);
    for (bytes[start..end]) |c| {
        switch (c) {
            '\n', '\r', ' ', '\t' => {},
            else => try clean.append(c),
        }
    }
    const dec = std.base64.standard.Decoder;
    const der = try arena.alloc(u8, try dec.calcSizeForSlice(clean.items));
    try dec.decode(der, clean.items);
    return der;
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
    var verbose = false;
    var mds_root: ?[]const u8 = null;
    var endpoints = std.array_list.Managed([]const u8).init(arena);

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
        } else if (std.mem.eql(u8, a, "--mds-root")) {
            mds_root = args.next();
        } else if (std.mem.eql(u8, a, "--mds-endpoint")) {
            if (args.next()) |u| try endpoints.append(u);
        } else if (std.mem.eql(u8, a, "--verbose")) {
            verbose = true;
        }
    }

    var store: passcay.mds.Store = .{ .entries = &.{} };
    var store_ptr: ?*const passcay.mds.Store = null;
    var all_entries = std.array_list.Managed(passcay.mds.Entry).init(arena);

    // Load live MDS3 blobs first so their status-bearing entries take priority
    // over any overlapping local statement (which carry no status reports).
    if (endpoints.items.len > 0) {
        const root_der = loadRootCert(io, arena, mds_root orelse {
            std.debug.print("--mds-endpoint requires --mds-root <cert>\n", .{});
            return error.MissingMdsRoot;
        }) catch |err| {
            std.debug.print("failed to load --mds-root: {s}\n", .{@errorName(err)});
            return err;
        };
        const anchors = [_][]const u8{root_der};
        for (endpoints.items) |url| {
            const blob = fetchUrl(io, gpa, arena, url) catch |err| {
                std.debug.print("MDS3 fetch failed for {s}: {s}\n", .{ url, @errorName(err) });
                continue;
            };
            const es = passcay.mds.parseBlob(arena, blob, &anchors, now_sec) catch |err| {
                std.debug.print("MDS3 blob rejected ({s}) for {s}\n", .{ @errorName(err), url });
                continue;
            };
            if (blobChainRevoked(io, gpa, arena, blob, root_der)) {
                std.debug.print("MDS3 blob rejected (signing certificate revoked) for {s}\n", .{url});
                continue;
            }
            try all_entries.appendSlice(es);
            std.debug.print("loaded {d} MDS3 entries from {s}\n", .{ es.len, url });
        }
    }

    if (metadata_dir) |dir_path| {
        const es = loadMetadata(io, arena, dir_path) catch |err| {
            std.debug.print("failed to load metadata from {s}: {s}\n", .{ dir_path, @errorName(err) });
            return err;
        };
        try all_entries.appendSlice(es);
        std.debug.print("loaded {d} metadata statement(s) from {s}\n", .{ es.len, dir_path });
    }

    if (all_entries.items.len > 0) {
        store.entries = all_entries.items;
        store_ptr = &store;
    }

    var app = App{ .ctx = srv.Context.init(gpa), .io = io, .verbose = verbose };
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
