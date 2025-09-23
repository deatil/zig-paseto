const std = @import("std");
const fmt = std.fmt;
const crypto = std.crypto;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const utils = @import("utils.zig");

pub const Ed25519 = std.crypto.sign.Ed25519;

pub const V4Public = EncodeV4Public("v4.public");

pub fn EncodeV4Public(comptime name: []const u8) type {
    return struct {
        alloc: Allocator,

        const Self = @This();

        const public_prefix = "v4.public.";
        const encoded_length = Ed25519.Signature.encoded_length;

        pub fn init(alloc: Allocator) Self {
            return .{
                .alloc = alloc,
            };
        }

        pub fn alg(self: Self) []const u8 {
            _ = self;
            return name;
        }

        // Sign a message (m) with the private key (sk).
        // PASETO v4 public signature primitive.
        // https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#sign
        pub fn encode(self: Self, r: std.Random, msg: []const u8, key: Ed25519.SecretKey, f: []const u8, i: []const u8) ![]u8 {
            _ = r;

            // Compute pre-authentication message
            const m2 = try utils.pre_auth_encoding(self.alloc, &[_][]const u8{ public_prefix, msg, f, i });
            defer self.alloc.free(m2);

            var secret_key = try Ed25519.KeyPair.fromSecretKey(key);

            const sig = try secret_key.sign(m2[0..], null);
            var siged = sig.toBytes();

            // Prepare content
            var out = try self.alloc.alloc(u8, msg.len + encoded_length);
            @memcpy(out[0..msg.len], msg[0..]);
            @memcpy(out[msg.len..][0..siged.len], siged[0..]);

            return out;
        }

        // PASETO v4 signature verification primitive.
        // https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#verify
        pub fn decode(self: Self, encoded: []const u8, key: Ed25519.PublicKey, f: []const u8, i: []const u8) ![]u8 {
            // Extract components
            const m = encoded[0 .. encoded.len - encoded_length];
            const s = encoded[encoded.len - encoded_length ..];

            // Compute pre-authentication message
            const m2 = try utils.pre_auth_encoding(self.alloc, &[_][]const u8{ public_prefix, m, f, i });
            defer self.alloc.free(m2);

            var signed: [encoded_length]u8 = undefined;
            @memcpy(signed[0..], s);

            const sig = Ed25519.Signature.fromBytes(signed);
            sig.verify(m2, key) catch {
                return error.PasetoInvalidTokenSignature;
            };

            return self.alloc.dupe(u8, m);
        }
    };
}

test "V4Public EncryptDecrypt" {
    const alloc = testing.allocator;
    const e = V4Public.init(alloc);

    const alg = e.alg();
    try testing.expectEqualStrings("v4.public", alg);

    const msg = "test-data";
    const f = "test-f";
    const i = "test-i";

    const kp = Ed25519.KeyPair.generate();

    const encoded = try e.encode(crypto.random, msg, kp.secret_key, f, i);
    defer alloc.free(encoded);

    // try testing.expectFmt(encoded_str, "{x}", .{encoded});
    try testing.expectEqual(true, encoded.len > 0);

    const res = try e.decode(encoded[0..], kp.public_key, f, i);
    defer alloc.free(res);

    try testing.expectFmt(msg, "{s}", .{res});
}

test "V4Public Decrypt check" {
    const key = "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2";

    var buf: [32]u8 = undefined;
    const k_bytes = try std.fmt.hexToBytes(&buf, key);

    const m = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const f = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
    const i = "{\"test-vector\":\"4-S-3\"}";

    const encoded = "7b2264617461223a22746869732069732061207369676e6564206d657373616765222c22657870223a22323032322d30312d30315430303a30303a30302b30303a3030227d34f59c8ae0f7774a397972571b9a49cbe0e2544a323d85acd58493c161cd26ae83643de37b981ffb4338251f62a5d51225b228bf398110279a5a66aa71a3f40d";

    var encoded2: [133]u8 = undefined;
    const encoded3 = try std.fmt.hexToBytes(&encoded2, encoded);

    var pubkey_bytes: [Ed25519.PublicKey.encoded_length]u8 = undefined;
    @memcpy(pubkey_bytes[0..], k_bytes);

    const pubkey = try Ed25519.PublicKey.fromBytes(pubkey_bytes);

    const alloc = testing.allocator;
    const e = V4Public.init(alloc);

    const res = try e.decode(encoded3[0..], pubkey, f, i);
    defer alloc.free(res);

    try testing.expectFmt(m, "{s}", .{res});
}

test "V4Public fail" {
    {
        const key = "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2";

        var buf: [32]u8 = undefined;
        const k_bytes = try std.fmt.hexToBytes(&buf, key);

        const f = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
        const i = "{\"test-vector\":\"4-S-3\"}";

        const encoded = "7b2264617461223a22746869732069732061207369676e6564206d657373616765222c22657870223a22323032322d30312d30315430303a30303a30302b30303a3030227d34f59c8ae0f7774a397972571b9a49cbe0e2544a323d85acd58493c161cd26ae83643de37b981ffb4338251f62a5d51225b228bf398110279a5a66aa71a3f40a";

        var encoded2: [133]u8 = undefined;
        const encoded3 = try std.fmt.hexToBytes(&encoded2, encoded);

        var pubkey_bytes: [Ed25519.PublicKey.encoded_length]u8 = undefined;
        @memcpy(pubkey_bytes[0..], k_bytes);

        const pubkey = try Ed25519.PublicKey.fromBytes(pubkey_bytes);

        const alloc = testing.allocator;
        const e = V4Public.init(alloc);

        var need_true: bool = false;
        _ = e.decode(encoded3[0..], pubkey, f, i) catch |err| {
            need_true = true;
            try testing.expectEqual(error.PasetoInvalidTokenSignature, err);
        };
        try testing.expectEqual(true, need_true);
    }
}
