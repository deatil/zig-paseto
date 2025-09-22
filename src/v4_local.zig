const std = @import("std");
const fmt = std.fmt;
const crypto = std.crypto;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const ChaCha20 = crypto.stream.chacha.XChaCha20IETF;

const v4 = @import("v4.zig");
const utils = @import("utils.zig");

pub const V4Local = EncodeV4Local("v4.local");

pub fn EncodeV4Local(comptime name: []const u8) type {
    return struct {
        alloc: Allocator,

        const Self = @This();

        const local_prefix = "v4.local.";

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

            // Generate random 32-byte nonce for ChaCha20-Poly1305
            var nonce: [32]u8 = undefined;
            r.bytes(&nonce);

            // Encrypt the JSON payload
            var ciphertext = try self.alloc.alloc(u8, msg.len);
            defer self.alloc.free(ciphertext);

            const kdf_res = try v4.kdf(key[0..], nonce[0..]);

            // Encrypt the payload
            ChaCha20.xor(
                ciphertext[0..],
                msg,
                0,
                kdf_res.ek[0..].*,
                kdf_res.n2[0..].*,
            );

            const t = try v4.mac(self.alloc, kdf_res.ak[0..], local_prefix, nonce[0..], ciphertext, f, i);

            // Combine nonce + ciphertext + t for base64 encoding
            var out = try self.alloc.alloc(u8, nonce.len + msg.len + t.len);
            @memcpy(out[0..nonce.len], nonce[0..]);
            @memcpy(out[nonce.len..][0..msg.len], ciphertext);
            @memcpy(out[nonce.len + msg.len ..][0..t.len], t[0..]);

            return out;
        }

        pub fn decode(self: Self, encoded: []const u8, key: []const u8, f: []const u8, i: []const u8) ![]u8 {
            if (key.len != 32) {
                return error.InvalidKeySize;
            }

            // Extract components
            const n = encoded[0..32];
            const t = encoded[encoded.len - 32 ..];
            const c = encoded[32 .. encoded.len - 32];

            const kdf_res = try v4.kdf(key[0..], n);

            const t2 = try v4.mac(self.alloc, kdf_res.ak[0..], local_prefix, n, c, f, i);
            if (!utils.eq(t2[0..], t)) {
                return error.PasetoInvalidPreAuthenticationHeader;
            }

            var out = try self.alloc.alloc(u8, c.len);

            // Decrypt the payload
            ChaCha20.xor(
                out[0..],
                c,
                0,
                kdf_res.ek[0..].*,
                kdf_res.n2[0..].*,
            );

            return out;
        }
    };
}

test "V4Local" {
    const alloc = testing.allocator;
    const e = V4Local.init(alloc);

    const alg = e.alg();
    try testing.expectEqualStrings("v4.local", alg);

    const msg = "test-data";
    const key = "test-keytest-keytest-keytest-key";
    const f = "test-f";
    const i = "test-i";

    const encoded = try e.encode(crypto.random, msg, key, f, i);
    defer alloc.free(encoded);

    // try testing.expectFmt(encoded_str, "{x}", .{encoded});
    try testing.expectEqual(true, encoded.len > 0);

    const res = try e.decode(encoded[0..], key, f, i);
    defer alloc.free(res);

    try testing.expectFmt(msg, "{s}", .{res});
}

test "V4Local EncryptDecrypt" {
    const key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

    var buf: [32]u8 = undefined;
    const k = try std.fmt.hexToBytes(&buf, key);

    const m = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const f = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
    const i = "{\"test-vector\":\"4-S-3\"}";

    const encoded = "459a60102b02cee79e781177e43a643d53760d972c53a17df4711d499dbc9475215401974dcd3a9018c8e8fc3ca96e18fda7235613b6d5d816b028329d0e76febc639b594d838bcd9fd5d03a6759f5eb11dc827b29abaa2dcf37bc0cf25c16fcc642111e056af2ce52aa10e25a6cdd2013ed2add99ba893b02ccbd4edaf3b8f9bea1de2c13";

    var encoded2: [133]u8 = undefined;
    const encoded3 = try std.fmt.hexToBytes(&encoded2, encoded);

    const alloc = testing.allocator;
    const e = V4Local.init(alloc);

    const res = try e.decode(encoded3[0..], k, f, i);
    defer alloc.free(res);

    try testing.expectFmt(m, "{s}", .{res});
}
