const std = @import("std");
const fmt = std.fmt;
const testing = std.testing;

pub const ecdsa = std.crypto.sign.ecdsa;
pub const Ed25519 = std.crypto.sign.Ed25519;

pub const der = @import("rsa/der.zig");
pub const oids = @import("rsa/oid.zig");
pub const utils = @import("utils.zig");

const oid_ecdsa_publickey = "1.2.840.10045.2.1";
const oid_ecdsa_p256_namedcurve = "1.2.840.10045.3.1.7";
const oid_ecdsa_p384_namedcurve = "1.3.132.0.34";
const oid_ecdsa_p521_namedcurve = "1.3.132.0.35";
const oid_ecdsa_s256_namedcurve = "1.3.132.0.10";

pub const ParseEcdsaP256Sha256Der = ParseEcdsaKeyDer(ecdsa.EcdsaP256Sha256, CheckEcdsaOid(oid_ecdsa_p256_namedcurve));
pub const ParseEcdsaP384Sha384Der = ParseEcdsaKeyDer(ecdsa.EcdsaP384Sha384, CheckEcdsaOid(oid_ecdsa_p384_namedcurve));
// pub const ParseEcdsaP521Sha512Der = ParseEcdsaKeyDer(ecdsa.EcdsaP521Sha512, CheckEcdsaOid(oid_ecdsa_p521_namedcurve));

pub const ParseEcdsaSecp256k1Sha256Der = ParseEcdsaKeyDer(ecdsa.EcdsaSecp256k1Sha256, CheckEcdsaOid(oid_ecdsa_s256_namedcurve));

/// check ECDSA namedcurve OID
pub fn CheckEcdsaOid(comptime namedcurve_oid: []const u8) type {
    return struct {
        const Self = @This();

        /// check oid
        pub fn check(oid: []const u8) !void {
            try checkECDSAPublickeyNamedCurveOid(oid, namedcurve_oid);
        }
    };
}

// parse ECDSA der key
pub fn ParseEcdsaKeyDer(comptime EC: type, comptime CheckOidFn: type) type {
    return struct {
        const Self = @This();

        pub fn parsePublicKeyDer(bytes: []const u8) !EC.PublicKey {
            var parser = der.Parser{ .bytes = bytes };
            _ = try parser.expectSequence();

            const oid_seq = try parser.expectSequence();
            const oid = try parser.expectOid();

            try checkECDSAPublickeyOid(oid);

            const namedcurve_oid = try parser.expectOid();

            try CheckOidFn.check(namedcurve_oid);

            parser.seek(oid_seq.slice.end);
            const pubkey = try parser.expectBitstring();

            return EC.PublicKey.fromSec1(pubkey.bytes);
        }

        pub fn parseSecretKeyDer(bytes: []const u8) !EC.SecretKey {
            return Self.parseECSecretKeyDer(bytes, null);
        }

        pub fn parseSecretKeyPKCS8Der(bytes: []const u8) !EC.SecretKey {
            var parser = der.Parser{ .bytes = bytes };
            _ = try parser.expectSequence();

            const version = try parser.expectInt(u8);
            if (version != 0) {
                return error.JWTEcdsaPKCS8VersionError;
            }

            const oid_seq = try parser.expectSequence();
            const oid = try parser.expectOid();

            try checkECDSAPublickeyOid(oid);

            const namedcurve_oid = try parser.expectOid();

            parser.seek(oid_seq.slice.end);
            const prikey_octet = try parser.expect(.universal, false, .octetstring);

            return Self.parseECSecretKeyDer(parser.view(prikey_octet), namedcurve_oid);
        }

        pub fn parseSecretKeyDerAuto(bytes: []const u8) !EC.SecretKey {
            const sk = Self.parseSecretKeyPKCS8Der(bytes) catch {
                return Self.parseSecretKeyDer(bytes);
            };

            return sk;
        }

        fn parseECSecretKeyDer(bytes: []const u8, oid: ?[]const u8) !EC.SecretKey {
            var parser = der.Parser{ .bytes = bytes };
            _ = try parser.expectSequence();

            const version = try parser.expectInt(u8);
            if (version != 1) {
                return error.JWTEcdsaECVersionError;
            }

            const prikey_octet = try parser.expect(.universal, false, .octetstring);
            const parse_prikey_bytes = parser.view(prikey_octet);

            var namedcurve_oid: []const u8 = "";
            if (oid) |val| {
                namedcurve_oid = val;
            } else {
                const oid_seq = try parser.expect(.context_specific, true, null);
                if (@intFromEnum(oid_seq.identifier.tag) != 0) {
                    return error.JWTEcdsaOidTagError;
                }
                namedcurve_oid = parser.expectOid() catch "";
            }

            try CheckOidFn.check(namedcurve_oid);

            var prikey: [EC.SecretKey.encoded_length]u8 = undefined;
            @memcpy(prikey[0..], parse_prikey_bytes);

            return EC.SecretKey.fromBytes(prikey);
        }
    };
}

fn checkECDSAPublickeyOid(oid: []const u8) !void {
    var buf: [256]u8 = undefined;
    var stream: std.Io.Writer = .fixed(&buf);
    try oids.decode(oid, &stream);

    const oid_string = stream.buffered();
    if (!std.mem.eql(u8, oid_string, oid_ecdsa_publickey)) {
        return error.JWTEcdsaOidError;
    }

    return;
}

fn checkECDSAPublickeyNamedCurveOid(oid: []const u8, namedcurve_oid: []const u8) !void {
    var buf: [256]u8 = undefined;
    var stream: std.Io.Writer = .fixed(&buf);
    try oids.decode(oid, &stream);

    const oid_string = stream.buffered();
    if (!std.mem.eql(u8, oid_string, namedcurve_oid)) {
        return error.JWTEcdsaNamedCurveNotSupport;
    }

    return;
}

// ===========================

const oid_eddsa_publickey = "1.3.101.112";

pub const ParseEddsaDer = ParseEdDSAKeyDer(Ed25519);

// parse EdDSA der key
pub fn ParseEdDSAKeyDer(comptime ED: type) type {
    return struct {
        const Self = @This();

        pub fn parseSecretKeyDer(bytes: []const u8) !ED.SecretKey {
            var parser = der.Parser{ .bytes = bytes };
            _ = try parser.expectSequence();

            const version = try parser.expectInt(u8);
            if (version != 0) {
                return error.JWTEdDSAPKCS8VersionError;
            }

            const oid_seq = try parser.expectSequence();
            const oid = try parser.expectOid();

            try checkEdDSAPublickeyOid(oid);

            parser.seek(oid_seq.slice.end);
            const prikey_octet = try parser.expect(.universal, false, .octetstring);

            var prikey_parser = der.Parser{ .bytes = parser.view(prikey_octet) };
            const prikey = try prikey_parser.expect(.universal, false, .octetstring);

            const parse_prikey_bytes = prikey_parser.view(prikey);
            if (parse_prikey_bytes.len != ED.KeyPair.seed_length) {
                return error.JWTEdDSASecretKeyBytesLengthError;
            }

            var seed: [ED.KeyPair.seed_length]u8 = undefined;
            @memcpy(seed[0..], parse_prikey_bytes);

            const kp = try ED.KeyPair.generateDeterministic(seed);

            return kp.secret_key;
        }

        pub fn parsePublicKeyDer(bytes: []const u8) !ED.PublicKey {
            var parser = der.Parser{ .bytes = bytes };
            _ = try parser.expectSequence();

            const oid_seq = try parser.expectSequence();
            const oid = try parser.expectOid();

            try checkEdDSAPublickeyOid(oid);

            parser.seek(oid_seq.slice.end);
            const pubkey = try parser.expectBitstring();

            if (pubkey.bytes.len != ED.PublicKey.encoded_length) {
                return error.JWTEdDSAPublicKeyBytesLengthError;
            }

            var pubkey_bytes: [ED.PublicKey.encoded_length]u8 = undefined;
            @memcpy(pubkey_bytes[0..], pubkey.bytes);

            return ED.PublicKey.fromBytes(pubkey_bytes);
        }
    };
}

fn checkEdDSAPublickeyOid(oid: []const u8) !void {
    var buf: [256]u8 = undefined;
    var stream: std.Io.Writer = .fixed(&buf);
    try oids.decode(oid, &stream);

    const oid_string = stream.buffered();
    if (!std.mem.eql(u8, oid_string, oid_eddsa_publickey)) {
        return error.JWTEdDSAOidError;
    }

    return;
}

test "ecdsa" {
    const alloc = testing.allocator;

    const prikey = "MIGkAgEBBDDqWgdCzllebram3uEH+cbKAjsu5xHwL/kZa97cfTJVdZ4j+IMj99PHZkdfxli2vo2gBwYFK4EEACKhZANiAAS5Zzmt6BAsk5mfpCqYBXK3PVy8Vgvkof3+8XLoRpq04PjnwLtdtY/M5pnMxsyWbIRbZHtB8Qkeb71EF+jg7WAtb9B013H1rvlbtVXu0uCmUE3J8hQ3EqY6ugmwqUUhi0M=";
    const pubkey = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuWc5regQLJOZn6QqmAVytz1cvFYL5KH9/vFy6EaatOD458C7XbWPzOaZzMbMlmyEW2R7QfEJHm+9RBfo4O1gLW/QdNdx9a75W7VV7tLgplBNyfIUNxKmOroJsKlFIYtD";

    const prikey_bytes = try utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try ParseEcdsaP384Sha384Der.parseSecretKeyDer(prikey_bytes);
    const public_key = try ParseEcdsaP384Sha384Der.parsePublicKeyDer(pubkey_bytes);

    const msg = "test-data";

    var sk = try ecdsa.EcdsaP384Sha384.KeyPair.fromSecretKey(secret_key);

    const sig = try sk.sign(msg[0..], null);
    const signed = sig.toBytes();

    try testing.expectEqual(true, signed.len > 0);

    const sig2 = ecdsa.EcdsaP384Sha384.Signature.fromBytes(signed);
    try sig2.verify(msg, public_key);
}

test "eddsa" {
    const alloc = testing.allocator;

    const prikey = "MC4CAQAwBQYDK2VwBCIEIE7YvvGJzvKQ3uZOQ6qAPkRsK7nkpmjPOaqsZKqrFQMw";
    const pubkey = "MCowBQYDK2VwAyEAgbbl7UO5W8ZMmOm+Kw9X2y9PyblBTDcZIRaR/kDFoA0=";

    const prikey_bytes = try utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try ParseEddsaDer.parseSecretKeyDer(prikey_bytes);
    const public_key = try ParseEddsaDer.parsePublicKeyDer(pubkey_bytes);

    const msg = "test-data";

    var sk = try Ed25519.KeyPair.fromSecretKey(secret_key);

    const sig = try sk.sign(msg[0..], null);
    const signed = sig.toBytes();

    try testing.expectEqual(true, signed.len > 0);

    const sig2 = Ed25519.Signature.fromBytes(signed);
    try sig2.verify(msg, public_key);
}
