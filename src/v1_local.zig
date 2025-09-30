const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const aes = crypto.core.aes;
const modes = crypto.core.modes;

const v1 = @import("v1.zig");
const utils = @import("utils.zig");

pub const V1Local = EncodeV1Local("v1.local");

pub fn EncodeV1Local(comptime name: []const u8) type {
    return struct {
        alloc: Allocator,

        const Self = @This();

        const local_prefix = "v1.local.";

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
            _ = i;

            if (key.len != 32) {
                return error.PasetoInvalidKeySize;
            }

            // Create random seed
            var rand_nonce: [32]u8 = undefined;
            r.bytes(&rand_nonce);

            const nonce = v1.hmac(rand_nonce[0..], msg);

            const kdf_res = try v1.kdf(key[0..], nonce[0..16]);

            var ciphertext = try self.alloc.alloc(u8, msg.len);
            defer self.alloc.free(ciphertext);

            // Encrypt the payload
            // Use an AES-256-CTR stream cipher
            const ctx = aes.Aes256.initEnc(kdf_res.ek[0..].*);
            modes.ctr(aes.AesEncryptCtx(aes.Aes256), ctx, ciphertext[0..], msg[0..], nonce[16..].*, std.builtin.Endian.big);

            const t = try v1.mac(self.alloc, kdf_res.ak[0..], local_prefix, nonce[0..], ciphertext, f);

            // Combine nonce + ciphertext + t for base64 encoding
            var out = try self.alloc.alloc(u8, nonce.len + msg.len + t.len);
            @memcpy(out[0..nonce.len], nonce[0..]);
            @memcpy(out[nonce.len..][0..msg.len], ciphertext);
            @memcpy(out[nonce.len + msg.len ..][0..t.len], t[0..]);

            return out;
        }

        pub fn decode(self: Self, encoded: []const u8, key: []const u8, f: []const u8, i: []const u8) ![]u8 {
            _ = i;

            if (key.len != 32) {
                return error.PasetoInvalidKeySize;
            }

            if (encoded.len < v1.nonce_length + v1.mac_length) {
                return error.PasetoIncorrectTokenFormat;
            }

            // Extract components
            const n = encoded[0..32];
            const t = encoded[encoded.len - 48 ..];
            const c = encoded[32 .. encoded.len - 48];

            const kdf_res = try v1.kdf(key[0..], n[0..16]);

            const t2 = try v1.mac(self.alloc, kdf_res.ak[0..], local_prefix, n, c, f);
            if (!utils.eq(t2[0..], t)) {
                return error.PasetoInvalidPreAuthenticationHeader;
            }

            var out = try self.alloc.alloc(u8, c.len);
            errdefer self.alloc.free(out);

            // Decrypt the payload
            // Use an AES-256-CTR stream cipher
            const ctx = aes.Aes256.initEnc(kdf_res.ek[0..].*);
            modes.ctr(aes.AesEncryptCtx(aes.Aes256), ctx, out[0..], c[0..], n[16..].*, std.builtin.Endian.big);

            return out;
        }
    };
}

test "V1Local EncryptDecrypt" {
    const alloc = testing.allocator;
    const e = V1Local.init(alloc);

    const alg = e.alg();
    try testing.expectEqualStrings("v1.local", alg);

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

test "V1Local Decrypt check" {
    const key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

    var buf: [32]u8 = undefined;
    const k = try std.fmt.hexToBytes(&buf, key);

    const m = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const f = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
    const i = "{\"test-vector\":\"1-S-3\"}";

    const encoded = "8ccacf422c54f3c8dc68a178677491164dbb853e8c66c93d96b959f569d7eb14510a344ffe5e59b33d61e3b2bf28aa1b2b9374f6288ea117b7b24dc4749a4c5c2bcc54601938294a868a8c545b6a19bbb58ec223fd8f66cdc0721ddb35aea10dff2a179bcb9868d339b6ef86e3279986bef2f9c8c20e1314a852788a4977dc7202179e8986b90b944e4e7a4f12793029863f874438";

    var encoded2: [149]u8 = undefined;
    const encoded3 = try std.fmt.hexToBytes(&encoded2, encoded);

    const alloc = testing.allocator;
    const e = V1Local.init(alloc);

    const res = try e.decode(encoded3[0..], k, f, i);
    defer alloc.free(res);

    try testing.expectFmt(m, "{s}", .{res});
}

test "V1Local fail" {
    {
        const key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e";

        var buf: [32]u8 = undefined;
        const k = try std.fmt.hexToBytes(&buf, key);

        const f = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
        const i = "{\"test-vector\":\"1-S-3\"}";

        const encoded = "8ccacf422c54f3c8dc68a178677491164dbb853e8c66c93d96b959f569d7eb14510a344ffe5e59b33d61e3b2bf28aa1b2b9374f6288ea117b7b24dc4749a4c5c2bcc54601938294a868a8c545b6a19bbb58ec223fd8f66cdc0721ddb35aea10dff2a179bcb9868d339b6ef86e3279986bef2f9c8c20e1314a852788a4977dc7202179e8986b90b944e4e7a4f12793029863f874438";

        var encoded2: [149]u8 = undefined;
        const encoded3 = try std.fmt.hexToBytes(&encoded2, encoded);

        const alloc = testing.allocator;
        const e = V1Local.init(alloc);

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
        const i = "{\"test-vector\":\"1-S-3\"}";

        const alloc = testing.allocator;
        const e = V1Local.init(alloc);

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
        const i = "{\"test-vector\":\"1-S-3\"}";

        const encoded = "8ccacf422c54f3c8dc68a178677491164dbb853e8c66c93d96b959f569d7eb14510a344ffe5e59b33d61e3b2bf28aa1b2b9374f6288ea117b7b24dc4749a4c5c2bcc54601938294a868a8c545b6a19bbb58ec223fd8f66cdc0721ddb35aea10dff2a179bcb9868d339b6ef86e3279986bef2f9c8c20e1314a852788a4977dc7202179e8986b90b944e4e7a4f12793029863f874439";

        var encoded2: [149]u8 = undefined;
        const encoded3 = try std.fmt.hexToBytes(&encoded2, encoded);

        const alloc = testing.allocator;
        const e = V1Local.init(alloc);

        var need_true: bool = false;
        _ = e.decode(encoded3[0..], k, f, i) catch |err| {
            need_true = true;
            try testing.expectEqual(error.PasetoInvalidPreAuthenticationHeader, err);
        };
        try testing.expectEqual(true, need_true);
    }

    {
        const key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

        var buf: [32]u8 = undefined;
        const k = try std.fmt.hexToBytes(&buf, key);

        const f = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
        const i = "{\"test-vector\":\"1-S-3\"}";

        const encoded = "8ccacf422c54f3c8dc68a178677491164dbb853e8c66c93d96b959f569d7eb1451";

        var encoded2: [33]u8 = undefined;
        const encoded3 = try std.fmt.hexToBytes(&encoded2, encoded);

        const alloc = testing.allocator;
        const e = V1Local.init(alloc);

        var need_true: bool = false;
        _ = e.decode(encoded3[0..], k, f, i) catch |err| {
            need_true = true;
            try testing.expectEqual(error.PasetoIncorrectTokenFormat, err);
        };
        try testing.expectEqual(true, need_true);
    }
}
