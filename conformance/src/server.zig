//! FIDO2 conformance server logic — transport-agnostic.
//!
//! Implements the four FIDO2 Server Conformance endpoints as pure functions
//! over the Passcay library. A thin HTTP shell (main.zig) wires these to routes;
//! the replay harness (test/replay.zig) drives them directly with recorded
//! transcripts. No hard-coded test bypasses: every result calls real library
//! verification and maps the outcome to the {status, errorMessage} envelope.
//!
//! State is username-centric: registration stores the credential under the
//! username that requested options (matched via the issued challenge), so
//! assertion options can return allowCredentials and the assertion can be
//! verified against the stored key.

const std = @import("std");
const Allocator = std.mem.Allocator;
const passcay = @import("passcay");

const List = std.array_list.Managed(u8);

pub const Response = struct {
    status: u16,
    body: []u8,

    pub fn deinit(self: Response, a: Allocator) void {
        a.free(self.body);
    }
};

pub const Credential = struct {
    id: []const u8, // credentialId, base64url
    public_key: []const u8, // COSE public key, base64url
    sign_count: u32 = 0,
};

const Session = struct {
    username: []const u8,
    require_uv: bool,
};

const CredList = std.array_list.Managed(Credential);

pub const Context = struct {
    gpa: Allocator,
    rp_id: []const u8 = "localhost",
    origin: []const u8 = "http://localhost:8080",
    mds: ?*const passcay.mds.Store = null,
    now_sec: ?i64 = null,
    /// Issued challenge -> ceremony session.
    sessions: std.StringHashMap(Session),
    /// username -> registered credentials.
    users: std.StringHashMap(CredList),

    pub fn init(gpa: Allocator) Context {
        return .{
            .gpa = gpa,
            .sessions = std.StringHashMap(Session).init(gpa),
            .users = std.StringHashMap(CredList).init(gpa),
        };
    }

    pub fn deinit(self: *Context) void {
        var si = self.sessions.iterator();
        while (si.next()) |e| {
            self.gpa.free(e.key_ptr.*);
            self.gpa.free(e.value_ptr.username);
        }
        self.sessions.deinit();

        var ui = self.users.iterator();
        while (ui.next()) |e| {
            self.gpa.free(e.key_ptr.*);
            for (e.value_ptr.items) |c| {
                self.gpa.free(c.id);
                self.gpa.free(c.public_key);
            }
            e.value_ptr.deinit();
        }
        self.users.deinit();
    }

    fn issueSession(self: *Context, challenge: []const u8, username: []const u8, require_uv: bool) !void {
        if (self.sessions.getEntry(challenge)) |e| {
            self.gpa.free(e.value_ptr.username);
            e.value_ptr.* = .{ .username = try self.gpa.dupe(u8, username), .require_uv = require_uv };
            return;
        }
        const k = try self.gpa.dupe(u8, challenge);
        errdefer self.gpa.free(k);
        const u = try self.gpa.dupe(u8, username);
        errdefer self.gpa.free(u);
        try self.sessions.put(k, .{ .username = u, .require_uv = require_uv });
    }

    fn consumeSession(self: *Context, challenge: []const u8) void {
        if (self.sessions.fetchRemove(challenge)) |kv| {
            self.gpa.free(kv.key);
            self.gpa.free(kv.value.username);
        }
    }

    fn addCredential(self: *Context, username: []const u8, id: []const u8, public_key: []const u8, sign_count: u32) !void {
        const gop = try self.users.getOrPut(username);
        if (!gop.found_existing) {
            gop.key_ptr.* = try self.gpa.dupe(u8, username);
            gop.value_ptr.* = CredList.init(self.gpa);
        }
        try gop.value_ptr.append(.{
            .id = try self.gpa.dupe(u8, id),
            .public_key = try self.gpa.dupe(u8, public_key),
            .sign_count = sign_count,
        });
    }

    fn userCreds(self: *Context, username: []const u8) []const Credential {
        if (self.users.get(username)) |list| return list.items;
        return &.{};
    }

    fn findCredMut(self: *Context, username: []const u8, id: []const u8) ?*Credential {
        const list = self.users.getPtr(username) orelse return null;
        for (list.items) |*c| {
            if (std.mem.eql(u8, c.id, id)) return c;
        }
        return null;
    }
};

// ---- helpers ----

fn okEmpty(a: Allocator) !Response {
    return .{ .status = 200, .body = try a.dupe(u8, "{\"status\":\"ok\",\"errorMessage\":\"\"}") };
}

fn fail(a: Allocator, message: []const u8) !Response {
    const body = try std.fmt.allocPrint(a, "{{\"status\":\"failed\",\"errorMessage\":\"{s}\"}}", .{message});
    return .{ .status = 400, .body = body };
}

fn isBase64Url(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '_' => {},
        else => return false,
    };
    return true;
}

/// JSON array of PublicKeyCredentialDescriptor for the given credentials.
fn credArray(a: Allocator, creds: []const Credential) ![]u8 {
    var list = List.init(a);
    defer list.deinit();
    try list.append('[');
    for (creds, 0..) |c, i| {
        if (i > 0) try list.append(',');
        try list.appendSlice("{\"type\":\"public-key\",\"id\":\"");
        try list.appendSlice(c.id);
        try list.appendSlice("\"}");
    }
    try list.append(']');
    return list.toOwnedSlice();
}

fn challengeFromClientData(a: Allocator, cdj_b64: []const u8) ![]u8 {
    const bytes = try passcay.util.decodeBase64Url(a, cdj_b64);
    defer a.free(bytes);
    const C = struct { challenge: []const u8 };
    var parsed = try std.json.parseFromSlice(C, a, bytes, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    return a.dupe(u8, parsed.value.challenge);
}

fn jsonValueString(a: Allocator, value: ?std.json.Value, default: []const u8) ![]u8 {
    if (value) |v| return std.fmt.allocPrint(a, "{f}", .{std.json.fmt(v, .{})});
    return a.dupe(u8, default);
}

fn objectStringField(v: std.json.Value, key: []const u8) ?[]const u8 {
    if (v != .object) return null;
    const got = v.object.get(key) orelse return null;
    if (got != .string) return null;
    return got.string;
}

// ---- request DTOs ----

const OptionsReq = struct {
    username: []const u8 = "user",
    displayName: []const u8 = "user",
    authenticatorSelection: ?std.json.Value = null,
    attestation: []const u8 = "none",
    extensions: ?std.json.Value = null,
};
const GetOptionsReq = struct {
    username: []const u8 = "user",
    userVerification: []const u8 = "preferred",
    extensions: ?std.json.Value = null,
};
const AttResultReq = struct {
    id: []const u8,
    type: []const u8,
    response: struct { clientDataJSON: []const u8, attestationObject: []const u8 },
};
const AsrResultReq = struct {
    id: []const u8,
    type: []const u8,
    response: struct { clientDataJSON: []const u8, authenticatorData: []const u8, signature: []const u8, userHandle: ?[]const u8 = null },
};

// ---- endpoints ----

/// POST /attestation/options
pub fn attestationOptions(ctx: *Context, a: Allocator, req_json: []const u8, challenge: []const u8) !Response {
    var parsed = std.json.parseFromSlice(OptionsReq, a, req_json, .{ .ignore_unknown_fields = true }) catch
        return fail(a, "invalid request");
    defer parsed.deinit();
    const r = parsed.value;

    const require_uv = if (r.authenticatorSelection) |sel|
        if (objectStringField(sel, "userVerification")) |uv| std.mem.eql(u8, uv, "required") else false
    else
        false;
    try ctx.issueSession(challenge, r.username, require_uv);

    const user_id = try passcay.util.encodeBase64Url(a, r.username);
    defer a.free(user_id);
    const exclude = try credArray(a, ctx.userCreds(r.username));
    defer a.free(exclude);
    const exts = try jsonValueString(a, r.extensions, "{\"example.extension\":\"loremipsum\"}");
    defer a.free(exts);
    const authsel_seg = if (r.authenticatorSelection) |sel| seg: {
        break :seg try std.fmt.allocPrint(a, ",\"authenticatorSelection\":{f}", .{std.json.fmt(sel, .{})});
    } else try a.dupe(u8, "");
    defer a.free(authsel_seg);

    const body = try std.fmt.allocPrint(a, "{{\"status\":\"ok\",\"errorMessage\":\"\",\"challenge\":\"{s}\"," ++
        "\"rp\":{{\"name\":\"Passcay\",\"id\":\"{s}\"}}," ++
        "\"user\":{{\"id\":\"{s}\",\"name\":\"{s}\",\"displayName\":\"{s}\"}}," ++
        "\"pubKeyCredParams\":[{{\"type\":\"public-key\",\"alg\":-7}},{{\"type\":\"public-key\",\"alg\":-8}}," ++
        "{{\"type\":\"public-key\",\"alg\":-35}},{{\"type\":\"public-key\",\"alg\":-47}}," ++
        "{{\"type\":\"public-key\",\"alg\":-37}},{{\"type\":\"public-key\",\"alg\":-38}}," ++
        "{{\"type\":\"public-key\",\"alg\":-39}},{{\"type\":\"public-key\",\"alg\":-257}}," ++
        "{{\"type\":\"public-key\",\"alg\":-258}},{{\"type\":\"public-key\",\"alg\":-259}}," ++
        "{{\"type\":\"public-key\",\"alg\":-65535}}]," ++
        "\"timeout\":60000,\"attestation\":\"{s}\",\"excludeCredentials\":{s}{s},\"extensions\":{s}}}", .{
        challenge, ctx.rp_id, user_id, r.username, r.displayName, r.attestation, exclude, authsel_seg, exts,
    });
    return .{ .status = 200, .body = body };
}

/// POST /attestation/result
pub fn attestationResult(ctx: *Context, a: Allocator, req_json: []const u8) !Response {
    var parsed = std.json.parseFromSlice(AttResultReq, a, req_json, .{ .ignore_unknown_fields = true }) catch
        return fail(a, "invalid request");
    defer parsed.deinit();
    const r = parsed.value;

    if (!std.mem.eql(u8, r.type, "public-key")) return fail(a, "type must be public-key");
    if (!isBase64Url(r.id)) return fail(a, "id must be base64url");

    const challenge = challengeFromClientData(a, r.response.clientDataJSON) catch
        return fail(a, "invalid clientDataJSON");
    defer a.free(challenge);
    const session = ctx.sessions.get(challenge) orelse return fail(a, "unknown or expired challenge");

    const result = passcay.register.verify(a, .{
        .attestation_object = r.response.attestationObject,
        .client_data_json = r.response.clientDataJSON,
    }, .{
        .challenge = challenge,
        .origin = ctx.origin,
        .rp_id = ctx.rp_id,
        .require_user_verification = session.require_uv,
        .attestation = .{ .now_sec = ctx.now_sec, .mds = ctx.mds },
    }) catch |err| return fail(a, errorMessage(err));
    defer result.deinit(a);

    ctx.addCredential(session.username, result.credential_id, result.public_key, result.sign_count) catch return fail(a, "storage error");
    ctx.consumeSession(challenge);
    return okEmpty(a);
}

/// POST /assertion/options
pub fn assertionOptions(ctx: *Context, a: Allocator, req_json: []const u8, challenge: []const u8) !Response {
    var parsed = std.json.parseFromSlice(GetOptionsReq, a, req_json, .{ .ignore_unknown_fields = true }) catch
        return fail(a, "invalid request");
    defer parsed.deinit();
    const r = parsed.value;

    try ctx.issueSession(challenge, r.username, std.mem.eql(u8, r.userVerification, "required"));

    const allow = try credArray(a, ctx.userCreds(r.username));
    defer a.free(allow);
    const exts = try jsonValueString(a, r.extensions, "{\"example.extension\":\"loremipsum\"}");
    defer a.free(exts);

    const body = try std.fmt.allocPrint(a, "{{\"status\":\"ok\",\"errorMessage\":\"\",\"challenge\":\"{s}\",\"timeout\":60000," ++
        "\"rpId\":\"{s}\",\"allowCredentials\":{s},\"userVerification\":\"{s}\",\"extensions\":{s}}}", .{
        challenge, ctx.rp_id, allow, r.userVerification, exts,
    });
    return .{ .status = 200, .body = body };
}

/// POST /assertion/result
pub fn assertionResult(ctx: *Context, a: Allocator, req_json: []const u8) !Response {
    var parsed = std.json.parseFromSlice(AsrResultReq, a, req_json, .{ .ignore_unknown_fields = true }) catch
        return fail(a, "invalid request");
    defer parsed.deinit();
    const r = parsed.value;

    if (!std.mem.eql(u8, r.type, "public-key")) return fail(a, "type must be public-key");
    if (!isBase64Url(r.id)) return fail(a, "id must be base64url");

    const challenge = challengeFromClientData(a, r.response.clientDataJSON) catch
        return fail(a, "invalid clientDataJSON");
    defer a.free(challenge);
    const session = ctx.sessions.get(challenge) orelse return fail(a, "unknown or expired challenge");

    const cred = ctx.findCredMut(session.username, r.id) orelse return fail(a, "unknown credential");

    const result = passcay.auth.verify(a, .{
        .authenticator_data = r.response.authenticatorData,
        .client_data_json = r.response.clientDataJSON,
        .signature = r.response.signature,
    }, .{
        .public_key = cred.public_key,
        .challenge = challenge,
        .origin = ctx.origin,
        .rp_id = ctx.rp_id,
        .require_user_verification = session.require_uv,
        .require_user_presence = true,
        .enable_sign_count_check = false,
    }) catch |err| return fail(a, errorMessage(err));
    defer result.deinit(a);

    // Clone detection: an authenticator that uses a sign counter (count seen
    // > 0) must strictly increase it. A counter that stays 0 means no counter.
    if (cred.sign_count != 0 and result.sign_count <= cred.sign_count) {
        return fail(a, "sign counter did not increase");
    }
    if (result.sign_count > cred.sign_count) cred.sign_count = result.sign_count;

    ctx.consumeSession(challenge);
    return okEmpty(a);
}

/// Map a library error to a stable, human-readable errorMessage.
pub fn errorMessage(err: anyerror) []const u8 {
    return switch (err) {
        error.ChallengeMismatch => "challenge mismatch",
        error.OriginMismatch => "origin mismatch",
        error.InvalidRpIdHash => "rpId hash mismatch",
        error.MissingUserPresenceFlag, error.UserPresenceFlagNotSet => "user presence flag not set",
        error.MissingUserVerificationFlag, error.UserVerificationRequired => "user verification required",
        error.SignatureVerificationFailed => "signature verification failed",
        error.AttestationSignatureInvalid => "invalid attestation signature",
        error.AttestationChainUntrusted => "attestation certificate chain not trusted",
        error.AttestationAaguidMismatch => "AAGUID mismatch",
        error.AttestationAaguidUnknown => "AAGUID not found in metadata",
        error.AttestationAuthenticatorCompromised => "authenticator status revoked or compromised",
        error.AttestationAlgorithmMismatch => "attestation algorithm mismatch",
        error.InvalidAttestationStatement => "invalid attestation statement",
        error.UnsupportedAttestationFormat => "unsupported attestation format",
        error.AttestationNotImplemented => "attestation format not implemented",
        error.InvalidClientDataType => "invalid clientData type",
        error.InvalidAttestationFormat => "invalid attestation object",
        else => @errorName(err),
    };
}
