const std = @import("std");
const crypto = std.crypto;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const hash_sha2 = std.crypto.hash.sha2;

pub const utils = @import("utils.zig");
pub const rsa = @import("rsa/rsa.zig");

pub const RsaPssSha384 = rsa.Pss(hash_sha2.Sha384);

pub const V1Public = EncodeV1Public("v1.public");

pub fn EncodeV1Public(comptime name: []const u8) type {
    return struct {
        alloc: Allocator,

        const Self = @This();

        const public_prefix = "v1.public.";

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
        // PASETO v1 public signature primitive.
        pub fn encode(self: Self, r: std.Random, msg: []const u8, key: rsa.SecretKey, f: []const u8, i: []const u8) ![]u8 {
            _ = r;
            _ = i;

            // Compute pre-authentication message
            const m2 = try utils.pre_auth_encoding(self.alloc, &[_][]const u8{ public_prefix, msg, f });
            defer self.alloc.free(m2);

            var signer = RsaPssSha384.Signer.init(key, null);
            signer.update(m2[0..]);

            var buf: [rsa.max_modulus_len]u8 = undefined;
            const sig = try signer.finalize(&buf);

            const signed = sig.toBytes();

            // Combine message + sign
            var out = try self.alloc.alloc(u8, msg.len + signed.len);
            @memcpy(out[0..msg.len], msg[0..]);
            @memcpy(out[msg.len..][0..signed.len], signed[0..]);

            return out;
        }

        // Verify PASETO v1 signature.
        pub fn decode(self: Self, encoded: []const u8, key: rsa.PublicKey, f: []const u8, i: []const u8) ![]u8 {
            _ = i;

            const sign_size = 256;

            // Extract components
            const m = encoded[0 .. encoded.len - sign_size];
            const s = encoded[encoded.len - sign_size ..];

            var s2 = try self.alloc.alloc(u8, s.len);
            defer self.alloc.free(s2);

            @memcpy(s2[0..], s[0..]);

            // Compute pre-authentication message
            const m2 = try utils.pre_auth_encoding(self.alloc, &[_][]const u8{ public_prefix, m, f });
            defer self.alloc.free(m2);

            var sig = RsaPssSha384.Signature.fromBytes(s2[0..]);
            sig.verify(m2, key, rsa.pss_salt_length_auto) catch {
                return error.PasetoInvalidTokenSignature;
            };

            return self.alloc.dupe(u8, m);
        }
    };
}

test "V1Public EncryptDecrypt" {
    const alloc = testing.allocator;
    const e = V1Public.init(alloc);

    const alg = e.alg();
    try testing.expectEqualStrings("v1.public", alg);

    const msg = "test-data";
    const f = "test-f";
    const i = "test-i";

    const prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq";
    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try rsa.SecretKey.fromDer(prikey_bytes);
    const public_key = try rsa.PublicKey.fromDer(pubkey_bytes);

    const encoded = try e.encode(crypto.random, msg, secret_key, f, i);
    defer alloc.free(encoded);

    try testing.expectEqual(true, encoded.len > 0);

    const res = try e.decode(encoded[0..], public_key, f, i);
    defer alloc.free(res);

    try testing.expectFmt(msg, "{s}", .{res});
}

test "V1Public Decrypt check" {
    const alloc = testing.allocator;

    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);
    defer alloc.free(pubkey_bytes);

    const public_key = try rsa.PublicKey.fromDer(pubkey_bytes);

    const m = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const f = "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}";
    const i = "{\"test-vector\":\"1-S-3\"}";

    const encoded = "7b2264617461223a22746869732069732061207369676e6564206d657373616765222c22657870223a22323032322d30312d30315430303a30303a30302b30303a3030227d408ffb43dda49db38d1ac28b01ebf810fcfaaecae238bdc78f70cf47274161e82a7ad81fc8efded99b30bb25bec7b87dfb64faa1c6bb9f0a8bfe5060bee1918de7f6ec7831f20ea4e4772ad18bbfb551d771b3442e6488f360c73d0b88b3159c93d74cceb214e0202e0a1334e81c050c8b2512e2f1cfb7c16ebb9ae7ee3c663bd4f6f78b3f11b9a6ab09fdfa7d0c918c66df81359f0a7945c87a173bb06cb2866192ef639b9befc6c8270b8aba7726dd29b41fe0a40d55795613fbb6ada07963dc737cb4c1c0a19e91eb056f3343d79da78771ac95f4ef8da2843bf3efbd1c5ec82ee7c1f8cff5c87d114af7b63204ce39cda35bf5b1a7ebe79bd821c75c0c4a";

    var encoded2: [325]u8 = undefined;
    const encoded3 = try std.fmt.hexToBytes(&encoded2, encoded);

    const e = V1Public.init(alloc);

    const res = try e.decode(encoded3[0..], public_key, f, i);
    defer alloc.free(res);

    try testing.expectFmt(m, "{s}", .{res});
}

test "V1Public fail" {
    {
        const alloc = testing.allocator;

        const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

        const pubkey_bytes = try utils.base64Decode(alloc, pubkey);
        defer alloc.free(pubkey_bytes);

        const public_key = try rsa.PublicKey.fromDer(pubkey_bytes);

        const f = "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}";
        const i = "{\"test-vector\":\"1-S-3\"}";

        const encoded = "7b2264617461223a22746869732069732061207369676e6564206d657373616765222c22657870223a22323032322d30312d30315430303a30303a30302b30303a3030227d408ffb43dda49db38d1ac28b01ebf810fcfaaecae238bdc78f70cf47274161e82a7ad81fc8efded99b30bb25bec7b87dfb64faa1c6bb9f0a8bfe5060bee1918de7f6ec7831f20ea4e4772ad18bbfb551d771b3442e6488f360c73d0b88b3159c93d74cceb214e0202e0a1334e81c050c8b2512e2f1cfb7c16ebb9ae7ee3c663bd4f6f78b3f11b9a6ab09fdfa7d0c918c66df81359f0a7945c87a173bb06cb2866192ef639b9befc6c8270b8aba7726dd29b41fe0a40d55795613fbb6ada07963dc737cb4c1c0a19e91eb056f3343d79da78771ac95f4ef8da2843bf3efbd1c5ec82ee7c1f8cff5c87d114af7b63204ce39cda35bf5b1a7ebe79bd821c75c0c4b";

        var encoded2: [325]u8 = undefined;
        const encoded3 = try std.fmt.hexToBytes(&encoded2, encoded);

        const e = V1Public.init(alloc);

        var need_true: bool = false;
        _ = e.decode(encoded3[0..], public_key, f, i) catch |err| {
            need_true = true;
            try testing.expectEqual(error.PasetoInvalidTokenSignature, err);
        };
        try testing.expectEqual(true, need_true);
    }
}
