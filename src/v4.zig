const std = @import("std");
const fmt = std.fmt;
const crypto = std.crypto;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const blake2 = std.crypto.hash.blake2;

const utils = @import("utils.zig");

// KeyLength is the requested encryption key size.
pub const key_length = 32;

pub const nonce_length = 32;
pub const mac_length = 32;
pub const encryption_kdf_length = 56;
pub const authentication_key_length = 32;

const KDFData = struct {
    ek: [32]u8 = undefined,
    n2: [24]u8 = undefined,
    ak: [32]u8 = undefined,
};

pub fn kdf(key: []const u8, n: []const u8) !KDFData {
    if (key.len != 32) {
        return error.KeySizeError;
    }

    const Blake2bKDF = blake2.Blake2b(encryption_kdf_length * 8);

    // Derive encryption key
    var enc_kdf = Blake2bKDF.init(.{
        .key = key,
    });

    var tmp: [Blake2bKDF.digest_length]u8 = undefined;

    // Domain separation (we use the same seed for 2 different purposes)
    enc_kdf.update("paseto-encryption-key");
    enc_kdf.update(n[0..]);
    enc_kdf.final(tmp[0..]);

    const Blake2bAuth = blake2.Blake2b(authentication_key_length * 8);

    // Derive authentication key
    var auth_kdf = Blake2bAuth.init(.{
        .key = key,
    });

    var ak: [Blake2bAuth.digest_length]u8 = undefined;

    // Domain separation (we use the same seed for 2 different purposes)
    auth_kdf.update("paseto-auth-key-for-aead");
    auth_kdf.update(n[0..]);
    auth_kdf.final(ak[0..]);

    // std.debug.print("tmp: {x} \n", .{tmp});

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

    const Blake2bMac = blake2.Blake2b(mac_length * 8);

    // Compute MAC
    var mac_hash = Blake2bMac.init(.{
        .key = ak,
    });

    var out: [Blake2bMac.digest_length]u8 = undefined;

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
    const res = try kdf(key[0..], n);
    try testing.expectFmt("0bc7afff982e05178d0b0a47e1cb3625a130fe01b9f47ac59d114f3abff56bb4", "{x}", .{res.ek});
    try testing.expectFmt("c3e56ba8da33052cf1311ae8155ca8c5913f638535d1d89c", "{x}", .{res.n2});
    try testing.expectFmt("651a7c5570c8661bebc0fca490826bf19a802c34b1d7b47c44151c591b0ecc92", "{x}", .{res.ak});
}

test "mac" {
    const ak = "test-ak";
    const h = "test-h";
    const n = "test-n";
    const c = "test-c";
    const f = "test-f";
    const i = "test-i";
    const res = try mac(testing.allocator, ak, h, n, c, f, i);
    try testing.expectFmt("1b3daf639c48e4231c3da79d3701b21695b359d8939d8511ad07ece1415bb9bc", "{x}", .{res});
}
