const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const utils = @import("utils.zig");

pub const Ed25519 = std.crypto.sign.Ed25519;

pub const V2Public = EncodeV2Public("v2.public");

pub fn EncodeV2Public(comptime name: []const u8) type {
    return struct {
        alloc: Allocator,

        const Self = @This();

        const public_prefix = "v2.public.";
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
        // PASETO v2 public signature primitive.
        pub fn encode(self: Self, r: std.Random, msg: []const u8, key: Ed25519.SecretKey, f: []const u8, i: []const u8) ![]u8 {
            _ = r;
            _ = i;

            var secret_key = try Ed25519.KeyPair.fromSecretKey(key);

            // Compute pre-authentication message
            const m2 = try utils.pre_auth_encoding(self.alloc, &[_][]const u8{ public_prefix, msg, f });
            defer self.alloc.free(m2);

            const sig = try secret_key.sign(m2[0..], null);
            var siged = sig.toBytes();

            // Combine msg + sign for base64 encoding
            var out = try self.alloc.alloc(u8, msg.len + encoded_length);
            @memcpy(out[0..msg.len], msg[0..]);
            @memcpy(out[msg.len..][0..siged.len], siged[0..]);

            return out;
        }

        // Verify PASETO v2 signature.
        pub fn decode(self: Self, encoded: []const u8, key: Ed25519.PublicKey, f: []const u8, i: []const u8) ![]u8 {
            _ = i;

            // Extract components
            const m = encoded[0 .. encoded.len - encoded_length];
            const s = encoded[encoded.len - encoded_length ..];

            // Compute pre-authentication message
            const m2 = try utils.pre_auth_encoding(self.alloc, &[_][]const u8{ public_prefix, m, f });
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

test "V2Public EncryptDecrypt" {
    const alloc = testing.allocator;
    const e = V2Public.init(alloc);

    const alg = e.alg();
    try testing.expectEqualStrings("v2.public", alg);

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

test "V2Public Decrypt check" {
    const key = "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2";

    var buf: [64]u8 = undefined;
    const k_bytes = try std.fmt.hexToBytes(&buf, key);

    const m = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const f = "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}";
    const i = "{\"test-vector\":\"2-S-3\"}";

    const encoded = "7b2264617461223a22746869732069732061207369676e6564206d657373616765222c22657870223a22323032322d30312d30315430303a30303a30302b30303a3030227dd0c8bcba97e58e7e3852c936653d9394f2a57d69eb68ca0fa66bea02a0073ef29876c29942ca9af5d650d99ea400ee447aae7416f26ea733f4dead245e01250e";

    var encoded2: [133]u8 = undefined;
    const encoded3 = try std.fmt.hexToBytes(&encoded2, encoded);

    var prikey_bytes: [Ed25519.SecretKey.encoded_length]u8 = undefined;
    @memcpy(prikey_bytes[0..], k_bytes);

    const prikey = try Ed25519.SecretKey.fromBytes(prikey_bytes);
    const kp = try Ed25519.KeyPair.fromSecretKey(prikey);
    const pubkey = kp.public_key;

    const alloc = testing.allocator;
    const e = V2Public.init(alloc);

    const res = try e.decode(encoded3[0..], pubkey, f, i);
    defer alloc.free(res);

    try testing.expectFmt(m, "{s}", .{res});
}

test "V2Public fail" {
    {
        const key = "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2";

        var buf: [32]u8 = undefined;
        const k_bytes = try std.fmt.hexToBytes(&buf, key);

        const f = "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}";
        const i = "{\"test-vector\":\"2-S-3\"}";

        const encoded = "7b2264617461223a22746869732069732061207369676e6564206d657373616765222c22657870223a22323032322d30312d30315430303a30303a30302b30303a3030227dd0c8bcba97e58e7e3852c936653d9394f2a57d69eb68ca0fa66bea02a0073ef29876c29942ca9af5d650d99ea400ee447aae7416f26ea733f4dead245e01250f";

        var encoded2: [133]u8 = undefined;
        const encoded3 = try std.fmt.hexToBytes(&encoded2, encoded);

        var pubkey_bytes: [Ed25519.PublicKey.encoded_length]u8 = undefined;
        @memcpy(pubkey_bytes[0..], k_bytes);

        const pubkey = try Ed25519.PublicKey.fromBytes(pubkey_bytes);

        const alloc = testing.allocator;
        const e = V2Public.init(alloc);

        var need_true: bool = false;
        _ = e.decode(encoded3[0..], pubkey, f, i) catch |err| {
            need_true = true;
            try testing.expectEqual(error.PasetoInvalidTokenSignature, err);
        };
        try testing.expectEqual(true, need_true);
    }
}
