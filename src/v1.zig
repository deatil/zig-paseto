const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const hkdf = std.crypto.kdf.hkdf;
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;

const utils = @import("utils.zig");

// KeyLength is the requested encryption key size.
pub const key_length = 32;

pub const nonce_length = 32;
pub const mac_length = 48;
pub const encryption_kdf_length = 32;
pub const authentication_key_length = 32;

pub fn hmac(n: []const u8, payload: []const u8) [32]u8 {
    var mac_hash = HmacSha384.init(n[0..]);

    var nonce: [mac_length]u8 = undefined;

    mac_hash.update(payload);
    mac_hash.final(nonce[0..]);

    var out: [32]u8 = undefined;
    @memcpy(out[0..], nonce[0..32]);

    return out;
}

const KDFData = struct {
    ek: [32]u8 = undefined,
    ak: [32]u8 = undefined,
};

pub fn kdf(key: []const u8, nonce: []const u8) !KDFData {
    if (key.len != 32) {
        return error.KeySizeError;
    }
    if (nonce.len != 16) {
        return error.NonceSizeError;
    }

    const encryption_key = "paseto-encryption-key";

    const enc_kdf = hkdf.Hkdf(HmacSha384);

    // Derive encryption key
    const prk = enc_kdf.extract(nonce[0..], key);

    var ek: [32]u8 = undefined;
    enc_kdf.expand(&ek, encryption_key, prk);

    // ===========

    const auth_key = "paseto-auth-key-for-aead";

    const auth_kdf = hkdf.Hkdf(HmacSha384);

    // Derive authentication key
    const prk2 = auth_kdf.extract(nonce[0..], key);

    // Get auth key (ak)
    var ak: [32]u8 = undefined;
    auth_kdf.expand(&ak, auth_key, prk2);

    var res: KDFData = .{};
    @memcpy(res.ek[0..], ek[0..]);
    @memcpy(res.ak[0..], ak[0..]);

    return res;
}

pub fn mac(alloc: Allocator, ak: []const u8, h: []const u8, n: []const u8, c: []const u8, f: []const u8) ![mac_length]u8 {
    // Compute pre-authentication message
    const pre_auth = try utils.pre_auth_encoding(alloc, &[_][]const u8{ h, n, c, f });
    defer alloc.free(pre_auth);

    // Compute MAC
    var mac_hash = HmacSha384.init(ak[0..]);

    var out: [mac_length]u8 = undefined;

    // Hash pre-authentication content
    mac_hash.update(pre_auth);
    mac_hash.final(out[0..]);

    return out;
}

test "hmac" {
    const n = "test-n";
    const payload = "test-payload";
    const res = hmac(n, payload);
    try testing.expectFmt("5b3168d7ead54ae33dfd45598fd691b541201683aba91e0b1bb77ba025298887", "{x}", .{res});
}

test "kdf" {
    var key: [32]u8 = undefined;
    @memcpy(key[0..4], "test");
    @memset(key[4..], 0);
    try testing.expectFmt("7465737400000000000000000000000000000000000000000000000000000000", "{x}", .{key});

    const n = "test-ntest-ntest";
    const res = try kdf(key[0..], n);
    try testing.expectFmt("09d804ac9d737397e57a06c3b78dd58675cf80a0cc89b220ee3da50c1376f8b0", "{x}", .{res.ek});
    try testing.expectFmt("7bc10f616c0677e58d29b8a0ecc895fb005a54182128576537df88700dd8a704", "{x}", .{res.ak});
}

test "mac" {
    const ak = "test-ak";
    const h = "test-h";
    const n = "test-n";
    const c = "test-c";
    const f = "test-f";
    const res = try mac(testing.allocator, ak, h, n, c, f);
    try testing.expectFmt("8721cc326cd23b4bc5003f99036b5afecd97c1df7ec17bd460be267c09bc30c630223568c4b92b65dfe0e67b3d4f89ba", "{x}", .{res});
}
