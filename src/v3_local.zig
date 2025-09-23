const std = @import("std");
const fmt = std.fmt;
const crypto = std.crypto;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const aes = crypto.core.aes;
const modes = crypto.core.modes;

const v3 = @import("v3.zig");
const utils = @import("utils.zig");

pub const V3Local = EncodeV3Local("v3.local");

pub fn EncodeV3Local(comptime name: []const u8) type {
    return struct {
        alloc: Allocator,

        const Self = @This();

        const local_prefix = "v3.local.";

        pub fn init(alloc: Allocator) Self {
            return .{
                .alloc = alloc,
            };
        }

        pub fn alg(self: Self) []const u8 {
            _ = self;
            return name;
        }

        pub fn encode(self: Self, r: std.Random, msg: []const u8, key: []const u8, f: []const u8, i: []const u8) ![]u8 {
            if (key.len != 32) {
                return error.PasetoInvalidKeySize;
            }

            // Create random seed
            var nonce: [32]u8 = undefined;
            r.bytes(&nonce);

            // Encrypt the JSON payload
            var ciphertext = try self.alloc.alloc(u8, msg.len);
            defer self.alloc.free(ciphertext);

            const kdf_res = try v3.kdf(self.alloc, key[0..], nonce[0..]);

            // Use an AES-256-CTR stream cipher
            const ctx = aes.Aes256.initEnc(kdf_res.ek[0..].*);
            modes.ctr(aes.AesEncryptCtx(aes.Aes256), ctx, ciphertext[0..], msg[0..], kdf_res.n2[0..].*, std.builtin.Endian.big);

            const t = try v3.mac(self.alloc, kdf_res.ak[0..], local_prefix, nonce[0..], ciphertext, f, i);

            // Combine nonce + ciphertext + t for base64 encoding
            var out = try self.alloc.alloc(u8, nonce.len + msg.len + t.len);
            @memcpy(out[0..nonce.len], nonce[0..]);
            @memcpy(out[nonce.len..][0..msg.len], ciphertext);
            @memcpy(out[nonce.len + msg.len ..][0..t.len], t[0..]);

            return out;
        }

        pub fn decode(self: Self, encoded: []const u8, key: []const u8, f: []const u8, i: []const u8) ![]u8 {
            if (key.len != 32) {
                return error.PasetoInvalidKeySize;
            }

            // Extract components
            const n = encoded[0..32];
            const t = encoded[encoded.len - 48 ..];
            const c = encoded[32 .. encoded.len - 48];

            const kdf_res = try v3.kdf(self.alloc, key[0..], n);

            const t2 = try v3.mac(self.alloc, kdf_res.ak[0..], local_prefix, n, c, f, i);
            if (!utils.eq(t2[0..], t)) {
                return error.PasetoInvalidPreAuthenticationHeader;
            }

            var out = try self.alloc.alloc(u8, c.len);

            // Use an AES-256-CTR stream cipher
            // Decrypt the payload
            const ctx = aes.Aes256.initEnc(kdf_res.ek[0..].*);
            modes.ctr(aes.AesEncryptCtx(aes.Aes256), ctx, out[0..], c[0..], kdf_res.n2[0..].*, std.builtin.Endian.big);

            return out;
        }
    };
}

test "V3Local EncryptDecrypt" {
    const alloc = testing.allocator;
    const e = V3Local.init(alloc);

    const alg = e.alg();
    try testing.expectEqualStrings("v3.local", alg);

    const msg = "test-data";
    const key = "test-keytest-keytest-keytest-key";
    const f = "test-f";
    const i = "test-i";

    const encoded = try e.encode(crypto.random, msg, key, f, i);
    defer alloc.free(encoded);

    try testing.expectEqual(true, encoded.len > 0);

    const res = try e.decode(encoded[0..], key, f, i);
    defer alloc.free(res);

    try testing.expectFmt(msg, "{s}", .{res});
}

test "V3Local Decrypt check" {
    const key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

    var buf: [32]u8 = undefined;
    const k = try std.fmt.hexToBytes(&buf, key);

    const m = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const f = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
    const i = "{\"test-vector\":\"4-S-3\"}";

    const encoded = "88e07beeebd7034c7af041e226c9b019e12d59bcbd5208360a26ff8c7f16b9ede8519e383d6b409d82e4c715ff93823e2bf007c1ccb5db904ad203ec85ec100872a857defe84e13eb5a3eefed714d437dfb57f3377c2fbe814e2b66d877b4f7606e88880c792f6d9e8417764405cad30be62efaa3286c61cdaffc12b7ebdb16fc7f3ba386137e58a18777296a2eb4e39ec729b80ae";

    var encoded2: [149]u8 = undefined;
    const encoded3 = try std.fmt.hexToBytes(&encoded2, encoded);

    const alloc = testing.allocator;
    const e = V3Local.init(alloc);

    const res = try e.decode(encoded3[0..], k, f, i);
    defer alloc.free(res);

    try testing.expectFmt(m, "{s}", .{res});
}

test "V3Local fail" {
    {
        const key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e";

        var buf: [32]u8 = undefined;
        const k = try std.fmt.hexToBytes(&buf, key);

        const f = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
        const i = "{\"test-vector\":\"4-S-3\"}";

        const encoded = "88e07beeebd7034c7af041e226c9b019e12d59bcbd5208360a26ff8c7f16b9ede8519e383d6b409d82e4c715ff93823e2bf007c1ccb5db904ad203ec85ec100872a857defe84e13eb5a3eefed714d437dfb57f3377c2fbe814e2b66d877b4f7606e88880c792f6d9e8417764405cad30be62efaa3286c61cdaffc12b7ebdb16fc7f3ba386137e58a18777296a2eb4e39ec729b80ae";

        var encoded2: [149]u8 = undefined;
        const encoded3 = try std.fmt.hexToBytes(&encoded2, encoded);

        const alloc = testing.allocator;
        const e = V3Local.init(alloc);

        var need_true: bool = false;
        _ = e.decode(encoded3[0..], k, f, i) catch |err| {
            need_true = true;
            try testing.expectEqual(error.PasetoInvalidKeySize, err);
        };
        try testing.expectEqual(true, need_true);
    }

    {
        const key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e";

        var buf: [32]u8 = undefined;
        const k = try std.fmt.hexToBytes(&buf, key);

        const msg = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
        const f = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
        const i = "{\"test-vector\":\"4-S-3\"}";

        const alloc = testing.allocator;
        const e = V3Local.init(alloc);

        var need_true: bool = false;
        _ = e.encode(crypto.random, msg, k, f, i) catch |err| {
            need_true = true;
            try testing.expectEqual(error.PasetoInvalidKeySize, err);
        };
        try testing.expectEqual(true, need_true);
    }

    {
        const key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

        var buf: [32]u8 = undefined;
        const k = try std.fmt.hexToBytes(&buf, key);

        const f = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
        const i = "{\"test-vector\":\"4-S-3\"}";

        const encoded = "88e07beeebd7034c7af041e226c9b019e12d59bcbd5208360a26ff8c7f16b9ede8519e383d6b409d82e4c715ff93823e2bf007c1ccb5db904ad203ec85ec100872a857defe84e13eb5a3eefed714d437dfb57f3377c2fbe814e2b66d877b4f7606e88880c792f6d9e8417764405cad30be62efaa3286c61cdaffc12b7ebdb16fc7f3ba386137e58a18777296a2eb4e39ec729b80a1";

        var encoded2: [149]u8 = undefined;
        const encoded3 = try std.fmt.hexToBytes(&encoded2, encoded);

        const alloc = testing.allocator;
        const e = V3Local.init(alloc);

        var need_true: bool = false;
        _ = e.decode(encoded3[0..], k, f, i) catch |err| {
            need_true = true;
            try testing.expectEqual(error.PasetoInvalidPreAuthenticationHeader, err);
        };
        try testing.expectEqual(true, need_true);
    }
}
