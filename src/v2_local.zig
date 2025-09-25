const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const XChaCha20Poly1305 = crypto.aead.chacha_poly.XChaCha20Poly1305;

const v2 = @import("v2.zig");
const utils = @import("utils.zig");

pub const V2Local = EncodeV2Local("v2.local");

pub fn EncodeV2Local(comptime name: []const u8) type {
    return struct {
        alloc: Allocator,

        const Self = @This();

        const local_prefix = "v2.local.";

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

            _ = i;

            // Create random seed
            var nonce: [24]u8 = undefined;
            r.bytes(&nonce);

            const n = v2.mac(nonce[0..], msg[0..]);

            const tag_len = XChaCha20Poly1305.tag_length;
            const nonce_length = XChaCha20Poly1305.nonce_length;

            const ciphertext_len = msg.len + tag_len;

            // Encrypt the payload
            var ciphertext = try self.alloc.alloc(u8, ciphertext_len);
            defer self.alloc.free(ciphertext);

            const m2 = try utils.pre_auth_encoding(self.alloc, &[_][]const u8{ local_prefix, n[0..], f });
            defer self.alloc.free(m2);

            XChaCha20Poly1305.encrypt(
                ciphertext[0..msg.len],
                ciphertext[msg.len..][0..tag_len],
                msg,
                m2,
                n[0..nonce_length].*,
                key[0..32].*,
            );

            // Combine nonce + ciphertext for base64 encoding
            var out = try self.alloc.alloc(u8, n.len + ciphertext_len);
            @memcpy(out[0..n.len], n[0..]);
            @memcpy(out[n.len..][0..ciphertext_len], ciphertext);

            return out;
        }

        pub fn decode(self: Self, encoded: []const u8, key: []const u8, f: []const u8, i: []const u8) ![]u8 {
            if (key.len != 32) {
                return error.PasetoInvalidKeySize;
            }

            _ = i;

            const tag_len = XChaCha20Poly1305.tag_length;
            const nonce_length = XChaCha20Poly1305.nonce_length;

            // Extract components
            const n = encoded[0..nonce_length];
            const c = encoded[nonce_length..];

            // Calculate plaintext length (ciphertext - auth tag)
            const plaintext_len = c.len - tag_len;

            const plaintext = try self.alloc.alloc(u8, plaintext_len);
            errdefer self.alloc.free(plaintext);

            // Split ciphertext and auth tag
            const ciphertext = c[0..plaintext_len];
            const auth_tag = c[plaintext_len..][0..tag_len];

            const m2 = try utils.pre_auth_encoding(self.alloc, &[_][]const u8{ local_prefix, n, f });
            defer self.alloc.free(m2);

            // Decrypt the payload
            XChaCha20Poly1305.decrypt(
                plaintext,
                ciphertext,
                auth_tag.*,
                m2,
                n[0..nonce_length].*,
                key[0..32].*,
            ) catch {
                return error.PasetoDecryptionFailed;
            };

            return plaintext;
        }
    };
}

test "V2Local EncryptDecrypt" {
    const alloc = testing.allocator;
    const e = V2Local.init(alloc);

    const alg = e.alg();
    try testing.expectEqualStrings("v2.local", alg);

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

test "V2Local Decrypt check" {
    const key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

    var buf: [32]u8 = undefined;
    const k = try std.fmt.hexToBytes(&buf, key);

    const m = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const f = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
    const i = "{\"test-vector\":\"2-S-3\"}";

    const encoded = "d9de5bb4903a06d575721f6f31caba28ab38bef6a4a50f0f8b6673b499949a679596a3a7e77f4868dfcee79cc1c0470b5174ac75750a279ba27d7d21a7d4c5aa08665e04114984d224cb4d0f1b9188b5876749e7b31d6cbde3c10f0a52d039e75fc65c316f45afbb1ab4595b56";

    var encoded2: [109]u8 = undefined;
    const encoded3 = try std.fmt.hexToBytes(&encoded2, encoded);

    const alloc = testing.allocator;
    const e = V2Local.init(alloc);

    const res = try e.decode(encoded3[0..], k, f, i);
    defer alloc.free(res);

    try testing.expectFmt(m, "{s}", .{res});
}

test "V2Local Decrypt check 2" {
    const key = "0000000000000000000000000000000000000000000000000000000000000000";

    var buf: [32]u8 = undefined;
    const k = try std.fmt.hexToBytes(&buf, key);

    const m = "";
    const f = "";

    const nonce = "000000000000000000000000000000000000000000000000";
    const token = "76b891361336d0640fbe559f2427a9ce1e877628c0abec8d52d2a9772e4a5e329fa522ab3a5a90bd";

    const test_rng: std.Random = .{
        .ptr = undefined,
        .fillFn = utils.TestRNG(nonce).fill,
    };

    const alloc = testing.allocator;
    const e = V2Local.init(alloc);

    const encoded = try e.encode(test_rng, m, k, f, "");
    defer alloc.free(encoded);

    try testing.expectFmt(token, "{x}", .{encoded});
}

test "V2Local fail" {
    {
        const key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e";

        var buf: [32]u8 = undefined;
        const k = try std.fmt.hexToBytes(&buf, key);

        const f = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
        const i = "{\"test-vector\":\"2-S-3\"}";

        const encoded = "d9de5bb4903a06d575721f6f31caba28ab38bef6a4a50f0f8b6673b499949a679596a3a7e77f4868dfcee79cc1c0470b5174ac75750a279ba27d7d21a7d4c5aa08665e04114984d224cb4d0f1b9188b5876749e7b31d6cbde3c10f0a52d039e75fc65c316f45afbb1ab4595b56";

        var encoded2: [109]u8 = undefined;
        const encoded3 = try std.fmt.hexToBytes(&encoded2, encoded);

        const alloc = testing.allocator;
        const e = V2Local.init(alloc);

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
        const e = V2Local.init(alloc);

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
        const i = "{\"test-vector\":\"2-S-3\"}";

        const encoded = "d9de5bb4903a06d575721f6f31caba28ab38bef6a4a50f0f8b6673b499949a679596a3a7e77f4868dfcee79cc1c0470b5174ac75750a279ba27d7d21a7d4c5aa08665e04114984d224cb4d0f1b9188b5876749e7b31d6cbde3c10f0a52d039e75fc65c316f45afbb1ab4595b57";

        var encoded2: [109]u8 = undefined;
        const encoded3 = try std.fmt.hexToBytes(&encoded2, encoded);

        const alloc = testing.allocator;
        const e = V2Local.init(alloc);

        var need_true: bool = false;
        _ = e.decode(encoded3[0..], k, f, i) catch |err| {
            need_true = true;
            try testing.expectEqual(error.PasetoDecryptionFailed, err);
        };
        try testing.expectEqual(true, need_true);
    }
}
