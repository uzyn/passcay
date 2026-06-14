//! FIDO2 conformance server logic — transport-agnostic.
//!
//! Implements the four FIDO2 Server Conformance endpoints as pure functions
//! over the Passcay library. A thin HTTP shell (main.zig) wires these to routes;
//! the replay harness (test/replay.zig) drives them directly with recorded
//! transcripts. No hard-coded test bypasses: every result calls real library
//! verification and maps the outcome to the {status, errorMessage} envelope.

const std = @import("std");
const Allocator = std.mem.Allocator;
const passcay = @import("passcay");

pub const Response = struct {
    status: u16,
    body: []u8,

    pub fn deinit(self: Response, a: Allocator) void {
        a.free(self.body);
    }
};

pub const Context = struct {
    gpa: Allocator,
    rp_id: []const u8 = "localhost",
    origin: []const u8 = "http://localhost:8080",
    require_uv: bool = false,
    /// FIDO metadata store for full attestation (AAGUID trust anchors + status).
    /// null leaves full attestation in lenient ("no metadata configured") mode.
    mds: ?*const passcay.mds.Store = null,
    /// Verification instant for certificate time validity (null = lenient).
    now_sec: ?i64 = null,
    /// Issued, not-yet-consumed challenges (anti-replay).
    issued: std.StringHashMap(void),
    /// Registered credentials: credentialId(b64url) -> publicKey(b64url).
    creds: std.StringHashMap([]const u8),

    pub fn init(gpa: Allocator) Context {
        return .{
            .gpa = gpa,
            .issued = std.StringHashMap(void).init(gpa),
            .creds = std.StringHashMap([]const u8).init(gpa),
        };
    }

    pub fn deinit(self: *Context) void {
        var ik = self.issued.keyIterator();
        while (ik.next()) |k| self.gpa.free(k.*);
        self.issued.deinit();
        var ci = self.creds.iterator();
        while (ci.next()) |e| {
            self.gpa.free(e.key_ptr.*);
            self.gpa.free(e.value_ptr.*);
        }
        self.creds.deinit();
    }

    fn issue(self: *Context, challenge: []const u8) !void {
        if (self.issued.contains(challenge)) return;
        const k = try self.gpa.dupe(u8, challenge);
        errdefer self.gpa.free(k);
        try self.issued.put(k, {});
    }

    fn consume(self: *Context, challenge: []const u8) bool {
        if (self.issued.fetchRemove(challenge)) |kv| {
            self.gpa.free(kv.key);
            return true;
        }
        return false;
    }

    fn storeCred(self: *Context, cred_id: []const u8, pubkey: []const u8) !void {
        if (self.creds.getEntry(cred_id)) |e| {
            const v = try self.gpa.dupe(u8, pubkey);
            self.gpa.free(e.value_ptr.*);
            e.value_ptr.* = v;
            return;
        }
        const k = try self.gpa.dupe(u8, cred_id);
        errdefer self.gpa.free(k);
        const v = try self.gpa.dupe(u8, pubkey);
        errdefer self.gpa.free(v);
        try self.creds.put(k, v);
    }
};

// ---- response helpers ----

fn okEmpty(a: Allocator) !Response {
    return .{ .status = 200, .body = try a.dupe(u8, "{\"status\":\"ok\",\"errorMessage\":\"\"}") };
}

fn fail(a: Allocator, message: []const u8) !Response {
    const body = try std.fmt.allocPrint(a, "{{\"status\":\"failed\",\"errorMessage\":\"{s}\"}}", .{message});
    return .{ .status = 400, .body = body };
}

// ---- request DTOs ----

const OptionsReq = struct { username: []const u8 = "user", displayName: []const u8 = "user" };
const AttResultReq = struct {
    id: []const u8,
    response: struct { clientDataJSON: []const u8, attestationObject: []const u8 },
};
const AsrResultReq = struct {
    id: []const u8,
    response: struct { clientDataJSON: []const u8, authenticatorData: []const u8, signature: []const u8, userHandle: ?[]const u8 = null },
};

fn challengeFromClientData(a: Allocator, cdj_b64: []const u8) ![]u8 {
    const bytes = try passcay.util.decodeBase64Url(a, cdj_b64);
    defer a.free(bytes);
    const C = struct { challenge: []const u8 };
    var parsed = try std.json.parseFromSlice(C, a, bytes, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    return a.dupe(u8, parsed.value.challenge);
}

// ---- endpoints ----

/// POST /attestation/options — registration options. The caller supplies the
/// freshly generated challenge (server: passcay.challenge.generate; tests: a
/// recorded fixed challenge).
pub fn attestationOptions(ctx: *Context, a: Allocator, req_json: []const u8, challenge: []const u8) !Response {
    var parsed = std.json.parseFromSlice(OptionsReq, a, req_json, .{ .ignore_unknown_fields = true }) catch
        return fail(a, "invalid request");
    defer parsed.deinit();

    try ctx.issue(challenge);

    const body = try std.fmt.allocPrint(a, "{{\"status\":\"ok\",\"errorMessage\":\"\",\"challenge\":\"{s}\"," ++
        "\"rp\":{{\"name\":\"Passcay\",\"id\":\"{s}\"}}," ++
        "\"user\":{{\"id\":\"dXNlcg\",\"name\":\"{s}\",\"displayName\":\"{s}\"}}," ++
        "\"pubKeyCredParams\":[{{\"type\":\"public-key\",\"alg\":-7}},{{\"type\":\"public-key\",\"alg\":-8}}," ++
        "{{\"type\":\"public-key\",\"alg\":-35}},{{\"type\":\"public-key\",\"alg\":-37}}," ++
        "{{\"type\":\"public-key\",\"alg\":-257}},{{\"type\":\"public-key\",\"alg\":-258}}," ++
        "{{\"type\":\"public-key\",\"alg\":-259}},{{\"type\":\"public-key\",\"alg\":-65535}}]," ++
        "\"timeout\":60000,\"attestation\":\"direct\",\"excludeCredentials\":[]}}", .{ challenge, ctx.rp_id, parsed.value.username, parsed.value.displayName });
    return .{ .status = 200, .body = body };
}

/// POST /attestation/result — verify a registration response.
pub fn attestationResult(ctx: *Context, a: Allocator, req_json: []const u8) !Response {
    var parsed = std.json.parseFromSlice(AttResultReq, a, req_json, .{ .ignore_unknown_fields = true }) catch
        return fail(a, "invalid request");
    defer parsed.deinit();
    const r = parsed.value;

    const challenge = challengeFromClientData(a, r.response.clientDataJSON) catch
        return fail(a, "invalid clientDataJSON");
    defer a.free(challenge);
    if (!ctx.issued.contains(challenge)) return fail(a, "unknown or expired challenge");

    const result = passcay.register.verify(a, .{
        .attestation_object = r.response.attestationObject,
        .client_data_json = r.response.clientDataJSON,
    }, .{
        .challenge = challenge,
        .origin = ctx.origin,
        .rp_id = ctx.rp_id,
        .require_user_verification = ctx.require_uv,
        .attestation = .{ .now_sec = ctx.now_sec, .mds = ctx.mds },
    }) catch |err| return fail(a, errorMessage(err));
    defer result.deinit(a);

    ctx.storeCred(result.credential_id, result.public_key) catch return fail(a, "storage error");
    _ = ctx.consume(challenge);
    return okEmpty(a);
}

/// POST /assertion/options — authentication options.
pub fn assertionOptions(ctx: *Context, a: Allocator, req_json: []const u8, challenge: []const u8) !Response {
    var parsed = std.json.parseFromSlice(OptionsReq, a, req_json, .{ .ignore_unknown_fields = true }) catch
        return fail(a, "invalid request");
    parsed.deinit();
    try ctx.issue(challenge);
    const body = try std.fmt.allocPrint(a, "{{\"status\":\"ok\",\"errorMessage\":\"\",\"challenge\":\"{s}\",\"timeout\":60000," ++
        "\"rpId\":\"{s}\",\"allowCredentials\":[],\"userVerification\":\"preferred\"}}", .{ challenge, ctx.rp_id });
    return .{ .status = 200, .body = body };
}

/// POST /assertion/result — verify an authentication assertion.
pub fn assertionResult(ctx: *Context, a: Allocator, req_json: []const u8) !Response {
    var parsed = std.json.parseFromSlice(AsrResultReq, a, req_json, .{ .ignore_unknown_fields = true }) catch
        return fail(a, "invalid request");
    defer parsed.deinit();
    const r = parsed.value;

    const pubkey = ctx.creds.get(r.id) orelse return fail(a, "unknown credential");

    const challenge = challengeFromClientData(a, r.response.clientDataJSON) catch
        return fail(a, "invalid clientDataJSON");
    defer a.free(challenge);
    if (!ctx.issued.contains(challenge)) return fail(a, "unknown or expired challenge");

    const result = passcay.auth.verify(a, .{
        .authenticator_data = r.response.authenticatorData,
        .client_data_json = r.response.clientDataJSON,
        .signature = r.response.signature,
    }, .{
        .public_key = pubkey,
        .challenge = challenge,
        .origin = ctx.origin,
        .rp_id = ctx.rp_id,
        .require_user_verification = false,
        .require_user_presence = true,
        .enable_sign_count_check = false,
    }) catch |err| return fail(a, errorMessage(err));
    defer result.deinit(a);

    _ = ctx.consume(challenge);
    return okEmpty(a);
}

/// Map a library error to a human-readable, stable errorMessage.
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
        error.InvalidAttestationStatement => "invalid attestation statement",
        error.UnsupportedAttestationFormat => "unsupported attestation format",
        error.InvalidClientDataType => "invalid clientData type",
        else => @errorName(err),
    };
}
