const std = @import("std");
const fmt = std.fmt;
const crypto = std.crypto;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const hkdf = std.crypto.kdf.hkdf;
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;

const utils = @import("utils.zig");

// KeyLength is the requested encryption key size.
pub const key_length = 32;

pub const nonce_length = 32;
pub const mac_length = 48;
pub const kdf_output_length = 48;
pub const signature_size = 96;

const KDFData = struct {
    ek: [32]u8 = undefined,
    n2: [16]u8 = undefined,
    ak: [48]u8 = undefined,
};

pub fn kdf(alloc: Allocator, key: []const u8, n: []const u8) !KDFData {
    if (key.len != 32) {
        return error.KeySizeError;
    }

    const encryption_key = "paseto-encryption-key";

    var context = try alloc.alloc(u8, encryption_key.len + n.len);
    defer alloc.free(context);

    @memcpy(context[0..encryption_key.len], encryption_key[0..]);
    @memcpy(context[encryption_key.len..], n[0..]);

    const enc_kdf = hkdf.Hkdf(HmacSha384);

    // Derive encryption key
    const salt = [_]u8{};
    const prk = enc_kdf.extract(&salt, key);

    // Split encryption key (Ek) and nonce (n2)
    var tmp: [48]u8 = undefined;
    enc_kdf.expand(&tmp, context, prk);

    // =======================

    const auth_key = "paseto-auth-key-for-aead";

    var context2 = try alloc.alloc(u8, auth_key.len + n.len);
    defer alloc.free(context2);

    @memcpy(context2[0..auth_key.len], auth_key[0..]);
    @memcpy(context2[auth_key.len..], n[0..]);

    const auth_kdf = hkdf.Hkdf(HmacSha384);

    // Derive authentication key
    const salt2 = [_]u8{};
    const prk2 = auth_kdf.extract(&salt2, key);

    // Split encryption key (Ek) and nonce (n2)
    var ak: [48]u8 = undefined;
    auth_kdf.expand(&ak, context2, prk2);

    var res: KDFData = .{};
    @memcpy(res.ek[0..], tmp[0..key_length]);
    @memcpy(res.n2[0..], tmp[key_length..]);
    @memcpy(res.ak[0..], ak[0..]);

    return res;
}

pub fn mac(alloc: Allocator, ak: []const u8, h: []const u8, n: []const u8, c: []const u8, f: []const u8, i: []const u8) ![mac_length]u8 {
    // Compute pre-authentication message
    const pre_auth = try utils.pre_auth_encoding(alloc, &[_][]const u8{ h, n, c, f, i });
    defer alloc.free(pre_auth);

    // Compute MAC
    var mac_hash = HmacSha384.init(ak[0..]);

    var out: [mac_length]u8 = undefined;

    // Hash pre-authentication content
    mac_hash.update(pre_auth);
    mac_hash.final(out[0..]);

    return out;
}

test "kdf" {
    var key: [32]u8 = undefined;
    @memcpy(key[0..4], "test");
    @memset(key[4..], 0);
    try testing.expectFmt("7465737400000000000000000000000000000000000000000000000000000000", "{x}", .{key});

    const n = "test-n";
    const res = try kdf(testing.allocator, key[0..], n);
    try testing.expectFmt("b9b1d282555d417f3b4c1b27fcb53237f399990d7b8b5dda466e11083f3062b4", "{x}", .{res.ek});
    try testing.expectFmt("5e3ee2fcb5ae1858b6da037abec4f21b", "{x}", .{res.n2});
    try testing.expectFmt("db69206c211f8460cc6526a9e0c0dedb249f9b67f053e547f7a1800a286c4e8ce57c9abd60424893cfe26d48c2125ac7", "{x}", .{res.ak});
}

test "mac" {
    const ak = "test-ak";
    const h = "test-h";
    const n = "test-n";
    const c = "test-c";
    const f = "test-f";
    const i = "test-i";
    const res = try mac(testing.allocator, ak, h, n, c, f, i);
    try testing.expectFmt("bf29d6fca9cb254f10a6069a367f4fe7f2d1741238b4483373aaeb2f11e1c2a62860917d44f510e8c30764731cc8907e", "{x}", .{res});
}
