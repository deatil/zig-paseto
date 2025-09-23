const std = @import("std");
const fmt = std.fmt;
const crypto = std.crypto;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const utils = @import("utils.zig");

pub const ecdsa = std.crypto.sign.ecdsa;
pub const EcdsaP384Sha384 = ecdsa.EcdsaP384Sha384;

pub const V3Public = EncodeV3Public("v3.public");

pub fn EncodeV3Public(comptime name: []const u8) type {
    return struct {
        alloc: Allocator,

        const Self = @This();

        const public_prefix = "v3.public.";
        const encoded_length = EcdsaP384Sha384.Signature.encoded_length;

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
        // PASETO v3 public signature primitive.
        // https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#sign
        pub fn encode(self: Self, r: std.Random, msg: []const u8, key: EcdsaP384Sha384.SecretKey, f: []const u8, i: []const u8) ![]u8 {
            _ = r;

            var secret_key = try EcdsaP384Sha384.KeyPair.fromSecretKey(key);

            const pk = secret_key.public_key.toCompressedSec1();

            // Compute pre-authentication message
            const m2 = try utils.pre_auth_encoding(self.alloc, &[_][]const u8{ pk[0..], public_prefix, msg, f, i });
            defer self.alloc.free(m2);

            const sig = try secret_key.sign(m2[0..], null);
            var siged = sig.toBytes();

            // Prepare content
            var out = try self.alloc.alloc(u8, msg.len + encoded_length);
            @memcpy(out[0..msg.len], msg[0..]);
            @memcpy(out[msg.len..][0..siged.len], siged[0..]);

            return out;
        }

        // Verify PASETO v3 signature.
        // https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#verify
        pub fn decode(self: Self, encoded: []const u8, key: EcdsaP384Sha384.PublicKey, f: []const u8, i: []const u8) ![]u8 {
            // Extract components
            const m = encoded[0 .. encoded.len - encoded_length];
            const s = encoded[encoded.len - encoded_length ..];

            const pk = key.toCompressedSec1();

            // Compute pre-authentication message
            const m2 = try utils.pre_auth_encoding(self.alloc, &[_][]const u8{ pk[0..], public_prefix, m, f, i });
            defer self.alloc.free(m2);

            var signed: [encoded_length]u8 = undefined;
            @memcpy(signed[0..], s);

            const sig = EcdsaP384Sha384.Signature.fromBytes(signed);
            sig.verify(m2, key) catch {
                return error.PasetoInvalidTokenSignature;
            };

            return self.alloc.dupe(u8, m);
        }
    };
}

test "V3Public EncryptDecrypt" {
    const alloc = testing.allocator;
    const e = V3Public.init(alloc);

    const alg = e.alg();
    try testing.expectEqualStrings("v3.public", alg);

    const msg = "test-data";
    const f = "test-f";
    const i = "test-i";

    const kp = EcdsaP384Sha384.KeyPair.generate();

    const encoded = try e.encode(crypto.random, msg, kp.secret_key, f, i);
    defer alloc.free(encoded);

    // try testing.expectFmt(encoded_str, "{x}", .{encoded});
    try testing.expectEqual(true, encoded.len > 0);

    const res = try e.decode(encoded[0..], kp.public_key, f, i);
    defer alloc.free(res);

    try testing.expectFmt(msg, "{s}", .{res});
}

test "V3Public Decrypt check" {
    const key = "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb";

    var buf: [49]u8 = undefined;
    const k_bytes = try std.fmt.hexToBytes(&buf, key);

    const m = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const f = "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}";
    const i = "{\"test-vector\":\"3-S-3\"}";

    const encoded = "7b2264617461223a22746869732069732061207369676e6564206d657373616765222c22657870223a22323032322d30312d30315430303a30303a30302b30303a3030227de128d621b8e64bbef5e468cb4a71e7a49ac2f59f9c9f02b8e5d9af9d5bc24500c208a01768a128a536a35f40ca631d57aabea071375faac70b0806e207878e5bd8e5b7ea0da9d1bc4e3b18122e9a96805f4f31750d77dfff8e6d1659c1ba4117";

    var encoded2: [165]u8 = undefined;
    const encoded3 = try std.fmt.hexToBytes(&encoded2, encoded);

    const pubkey = try EcdsaP384Sha384.PublicKey.fromSec1(k_bytes[0..]);

    const alloc = testing.allocator;
    const e = V3Public.init(alloc);

    const res = try e.decode(encoded3[0..], pubkey, f, i);
    defer alloc.free(res);

    try testing.expectFmt(m, "{s}", .{res});
}

test "V3Public fail" {
    {
        const key = "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb";

        var buf: [49]u8 = undefined;
        const k_bytes = try std.fmt.hexToBytes(&buf, key);

        const f = "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}";
        const i = "{\"test-vector\":\"3-S-3\"}";

        const encoded = "7b2264617461223a22746869732069732061207369676e6564206d657373616765222c22657870223a22323032322d30312d30315430303a30303a30302b30303a3030227de128d621b8e64bbef5e468cb4a71e7a49ac2f59f9c9f02b8e5d9af9d5bc24500c208a01768a128a536a35f40ca631d57aabea071375faac70b0806e207878e5bd8e5b7ea0da9d1bc4e3b18122e9a96805f4f31750d77dfff8e6d1659c1ba4116";

        var encoded2: [165]u8 = undefined;
        const encoded3 = try std.fmt.hexToBytes(&encoded2, encoded);

        const pubkey = try EcdsaP384Sha384.PublicKey.fromSec1(k_bytes[0..]);

        const alloc = testing.allocator;
        const e = V3Public.init(alloc);

        var need_true: bool = false;
        _ = e.decode(encoded3[0..], pubkey, f, i) catch |err| {
            need_true = true;
            try testing.expectEqual(error.PasetoInvalidTokenSignature, err);
        };
        try testing.expectEqual(true, need_true);
    }
}
