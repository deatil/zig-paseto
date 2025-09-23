const std = @import("std");
const testing = std.testing;
const crypto = std.crypto;

pub const paseto = @import("paseto.zig");

test "V4Local EncryptDecrypt" {
    const key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

    var buf: [32]u8 = undefined;
    const k = try std.fmt.hexToBytes(&buf, key);

    const m = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const f = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
    const i = "{\"test-vector\":\"4-S-3\"}";

    const alloc = testing.allocator;

    var e = paseto.V4Local.init(alloc);
    defer e.deinit();

    try e.withMessage(m);
    try e.withFooter(f);
    try e.withImplicit(i);

    const token = try e.encode(crypto.random, k);
    defer alloc.free(token);

    // ==================

    var p = paseto.V4Local.init(alloc);
    defer p.deinit();

    try p.withImplicit(i);

    try p.decode(token, k);

    try testing.expectFmt(m, "{s}", .{p.message});
    try testing.expectFmt(f, "{s}", .{p.footer});
    try testing.expectFmt(i, "{s}", .{p.implicit});

    const g_m = try p.getMessage();
    defer g_m.deinit();
    try testing.expectEqualStrings("this is a signed message", g_m.value.object.get("data").?.string);

    const MessageT = struct {
        data: []const u8,
        exp: []const u8,
    };

    const g_m2 = try p.getMessageT(MessageT);
    defer g_m2.deinit();
    try testing.expectEqualStrings("this is a signed message", g_m2.value.data);
    try testing.expectEqualStrings("2022-01-01T00:00:00+00:00", g_m2.value.exp);

    const g_f = try p.getFooter();
    defer g_f.deinit();
    try testing.expectEqualStrings("zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN", g_f.value.object.get("kid").?.string);

    const FooterT = struct {
        kid: []const u8,
    };

    const g_f2 = try p.getFooterT(FooterT);
    defer g_f2.deinit();
    try testing.expectEqualStrings("zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN", g_f2.value.kid);

    const g_i = try p.getImplicit();
    defer g_i.deinit();
    try testing.expectEqualStrings("4-S-3", g_i.value.object.get("test-vector").?.string);

    const ImplicitT = struct {
        @"test-vector": []const u8,
    };

    const g_i2 = try p.getImplicitT(ImplicitT);
    defer g_i2.deinit();
    try testing.expectEqualStrings("4-S-3", g_i2.value.@"test-vector");
}

test "V4Local EncryptDecrypt Use Set" {
    const key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

    var buf: [32]u8 = undefined;
    const k = try std.fmt.hexToBytes(&buf, key);

    const m = .{
        .data = "this is a signed message",
        .exp = "2022-01-01T00:00:00+00:00",
    };
    const f = .{
        .kid = "zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN",
    };
    const i = .{
        .@"test-vector" = "4-S-3",
    };

    const alloc = testing.allocator;

    var e = paseto.V4Local.init(alloc);
    defer e.deinit();

    try e.setMessage(m);
    try e.setFooter(f);
    try e.setImplicit(i);

    const token = try e.encode(crypto.random, k);
    defer alloc.free(token);

    // ==================

    var p = paseto.V4Local.init(alloc);
    defer p.deinit();

    try p.setImplicit(i);

    try p.decode(token, k);

    const g_m = try p.getMessage();
    defer g_m.deinit();
    try testing.expectEqualStrings("this is a signed message", g_m.value.object.get("data").?.string);

    const MessageT = struct {
        data: []const u8,
        exp: []const u8,
    };

    const g_m2 = try p.getMessageT(MessageT);
    defer g_m2.deinit();
    try testing.expectEqualStrings("this is a signed message", g_m2.value.data);
    try testing.expectEqualStrings("2022-01-01T00:00:00+00:00", g_m2.value.exp);

    const g_f = try p.getFooter();
    defer g_f.deinit();
    try testing.expectEqualStrings("zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN", g_f.value.object.get("kid").?.string);

    const FooterT = struct {
        kid: []const u8,
    };

    const g_f2 = try p.getFooterT(FooterT);
    defer g_f2.deinit();
    try testing.expectEqualStrings("zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN", g_f2.value.kid);

    const g_i = try p.getImplicit();
    defer g_i.deinit();
    try testing.expectEqualStrings("4-S-3", g_i.value.object.get("test-vector").?.string);

    const ImplicitT = struct {
        @"test-vector": []const u8,
    };

    const g_i2 = try p.getImplicitT(ImplicitT);
    defer g_i2.deinit();
    try testing.expectEqualStrings("4-S-3", g_i2.value.@"test-vector");
}

test "V4Local EncryptDecrypt Check" {
    const key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

    var buf: [32]u8 = undefined;
    const k = try std.fmt.hexToBytes(&buf, key);

    const m = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const f = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
    const i = "{\"test-vector\":\"4-S-3\"}";

    const token = "v4.local.RZpgECsCzueeeBF35DpkPVN2DZcsU6F99HEdSZ28lHUhVAGXTc06kBjI6Pw8qW4Y_acjVhO21dgWsCgynQ52_rxjm1lNg4vNn9XQOmdZ9esR3IJ7KauqLc83vAzyXBb8xkIRHgVq8s5SqhDiWmzdIBPtKt2Zuok7Asy9TtrzuPm-od4sEw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

    const alloc = testing.allocator;

    var p = paseto.V4Local.init(alloc);
    defer p.deinit();

    try p.withImplicit(i);

    try p.decode(token, k);

    try testing.expectFmt(m, "{s}", .{p.message});
    try testing.expectFmt(f, "{s}", .{p.footer});
    try testing.expectFmt(i, "{s}", .{p.implicit});
}

test "V4Local Decrypt fail" {
    {
        const key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

        var buf: [32]u8 = undefined;
        const k = try std.fmt.hexToBytes(&buf, key);

        const i = "{\"test-vector\":\"4-S-3\"}";

        const token = "v4.local2.RZpgECsCzueeeBF35DpkPVN2DZcsU6F99HEdSZ28lHUhVAGXTc06kBjI6Pw8qW4Y_acjVhO21dgWsCgynQ52_rxjm1lNg4vNn9XQOmdZ9esR3IJ7KauqLc83vAzyXBb8xkIRHgVq8s5SqhDiWmzdIBPtKt2Zuok7Asy9TtrzuPm-od4sEw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";

        const alloc = testing.allocator;

        var p = paseto.V4Local.init(alloc);
        defer p.deinit();

        try p.withImplicit(i);

        var need_true: bool = false;
        _ = p.decode(token, k) catch |err| {
            need_true = true;
            try testing.expectEqual(paseto.Error.PasetoTokAlgoInvalid, err);
        };
        try testing.expectEqual(true, need_true);
    }

    {
        const key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

        var buf: [32]u8 = undefined;
        const k = try std.fmt.hexToBytes(&buf, key);

        const i = "{\"test-vector\":\"4-S-3\"}";

        const token = "v4-local.RZpgECsCzueeeBF35DpkPVN2DZcsU6F99HEdSZ28lHUhVAGXTc06kBjI6Pw8qW4Y_acjVhO21dgWsCgynQ52_rxjm1lNg4vNn9XQOmdZ9esR3IJ7KauqLc83vAzyXBb8xkIRHgVq8s5SqhDiWmzdIBPtKt2Zuok7Asy9TtrzuPm-od4sEw";

        const alloc = testing.allocator;

        var p = paseto.V4Local.init(alloc);
        defer p.deinit();

        try p.withImplicit(i);

        var need_true: bool = false;
        _ = p.decode(token, k) catch |err| {
            need_true = true;
            try testing.expectEqual(paseto.Error.PasetoTokenInvalid, err);
        };
        try testing.expectEqual(true, need_true);
    }
}

pub fn TestRNG(comptime buf: []const u8) type {
    return struct {
        fn fill(_: *anyopaque, buffer: []u8) void {
            var buf2: [32]u8 = undefined;
            const buf3 = std.fmt.hexToBytes(&buf2, buf) catch "";

            if (buffer.len < buf3.len) {
                @memcpy(buffer[0..], buf3[0..buffer.len]);
            } else {
                @memcpy(buffer[0..buf3.len], buf3[0..]);
            }
        }
    };
}

test "TestRNG" {
    const test_rng: std.Random = .{
        .ptr = undefined,
        .fillFn = TestRNG("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f").fill,
    };

    var buf: [5]u8 = undefined;
    test_rng.bytes(&buf);

    try testing.expectFmt("7071727374", "{x}", .{buf[0..]});
}

fn testV4LocalVectorT(comptime nonce: []const u8) type {
    return struct {
        fn testLocalVector(
            key: []const u8,
            token: []const u8,
            payload: []const u8,
            footer: []const u8,
            implicit_assertion: []const u8,
        ) !void {
            var buf: [32]u8 = undefined;
            const k = try std.fmt.hexToBytes(&buf, key);

            const test_rng: std.Random = .{
                .ptr = undefined,
                .fillFn = TestRNG(nonce).fill,
            };

            const alloc = testing.allocator;

            var e = paseto.V4Local.init(alloc);
            defer e.deinit();

            try e.withMessage(payload);
            try e.withFooter(footer);
            try e.withImplicit(implicit_assertion);

            const encoded = try e.encode(test_rng, k);
            defer alloc.free(encoded);

            try testing.expectFmt(token, "{s}", .{encoded});

            // ==================

            var p = paseto.V4Local.init(alloc);
            defer p.deinit();

            try p.withImplicit(implicit_assertion);

            try p.decode(token, k);

            try testing.expectFmt(payload, "{s}", .{p.message});
        }
    };
}

test "v4 LocalVector" {
    // https://github.com/paseto-standard/test-vectors/blob/master/v4.json

    // 4-E-1
    try testV4LocalVectorT("0000000000000000000000000000000000000000000000000000000000000000").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg",
        "{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "",
        "",
    );
    // 4-E-2
    try testV4LocalVectorT("0000000000000000000000000000000000000000000000000000000000000000").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvS2csCgglvpk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XIemu9chy3WVKvRBfg6t8wwYHK0ArLxxfZP73W_vfwt5A",
        "{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "",
        "",
    );
    // 4-E-3
    try testV4LocalVectorT("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6-tyebyWG6Ov7kKvBdkrrAJ837lKP3iDag2hzUPHuMKA",
        "{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "",
        "",
    );
    // 4-E-4
    try testV4LocalVectorT("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4gt6TiLm55vIH8c_lGxxZpE3AWlH4WTR0v45nsWoU3gQ",
        "{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "",
        "",
    );
    // 4-E-5
    try testV4LocalVectorT("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        "{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}",
        "",
    );
    // 4-E-6
    try testV4LocalVectorT("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6pWSA5HX2wjb3P-xLQg5K5feUCX4P2fpVK3ZLWFbMSxQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        "{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}",
        "",
    );
    // 4-E-7
    try testV4LocalVectorT("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t40KCCWLA7GYL9KFHzKlwY9_RnIfRrMQpueydLEAZGGcA.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        "{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}",
        "{\"test-vector\":\"4-E-7\"}",
    );
    // 4-E-8
    try testV4LocalVectorT("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t5uvqQbMGlLLNYBc7A6_x7oqnpUK5WLvj24eE4DVPDZjw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        "{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}",
        "{\"test-vector\":\"4-E-8\"}",
    );
    // 4-E-9
    try testV4LocalVectorT("df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6tybdlmnMwcDMw0YxA_gFSE_IUWl78aMtOepFYSWYfQA.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24",
        "{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "arbitrary-string-that-isn't-json",
        "{\"test-vector\":\"4-E-9\"}",
    );
}

// ======================================

test "V4Public EncryptDecrypt" {
    const kp = paseto.Ed25519.KeyPair.generate();

    const m = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const f = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
    const i = "{\"test-vector\":\"4-S-3\"}";

    const alloc = testing.allocator;

    var e = paseto.V4Public.init(alloc);
    defer e.deinit();

    try e.withMessage(m);
    try e.withFooter(f);
    try e.withImplicit(i);

    const token = try e.encode(crypto.random, kp.secret_key);
    defer alloc.free(token);

    // ==================

    var p = paseto.V4Public.init(alloc);
    defer p.deinit();

    try p.withImplicit(i);

    try p.decode(token, kp.public_key);

    try testing.expectFmt(m, "{s}", .{p.message});
    try testing.expectFmt(f, "{s}", .{p.footer});
    try testing.expectFmt(i, "{s}", .{p.implicit});
}

fn testV4PublicVector(
    public_key: []const u8,
    secret_key: []const u8,
    secret_key_seed: []const u8,
    token: []const u8,
    payload: []const u8,
    footer: []const u8,
    implicit_assertion: []const u8,
) !void {
    var buf3: [32]u8 = undefined;
    const pub_key_seed = try std.fmt.hexToBytes(&buf3, secret_key_seed);

    var seed: [paseto.Ed25519.KeyPair.seed_length]u8 = undefined;
    @memcpy(seed[0..], pub_key_seed);

    const kp = try paseto.Ed25519.KeyPair.generateDeterministic(seed);

    const sk = kp.secret_key;
    const pk = kp.public_key;

    try testing.expectFmt(secret_key, "{x}", .{sk.bytes});
    try testing.expectFmt(public_key, "{x}", .{pk.bytes});

    // =====================

    const alloc = testing.allocator;

    var e = paseto.V4Public.init(alloc);
    defer e.deinit();

    try e.withMessage(payload);
    try e.withFooter(footer);
    try e.withImplicit(implicit_assertion);

    const encoded = try e.encode(crypto.random, sk);
    defer alloc.free(encoded);

    try testing.expectFmt(token, "{s}", .{encoded});

    // ==================

    var p = paseto.V4Public.init(alloc);
    defer p.deinit();

    try p.withImplicit(implicit_assertion);

    try p.decode(token, pk);

    try testing.expectFmt(payload, "{s}", .{p.message});
}

test "v4 PublicVector" {
    // https://github.com/paseto-standard/test-vectors/blob/master/v4.json

    // 4-S-1
    try testV4PublicVector(
        "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
        "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
        "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774",
        "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA",
        "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "",
        "",
    );
    // 4-S-2
    try testV4PublicVector(
        "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
        "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
        "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774",
        "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}",
        "",
    );
    // 4-S-3
    try testV4PublicVector(
        "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
        "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
        "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774",
        "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NPWciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
        "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}",
        "{\"test-vector\":\"4-S-3\"}",
    );
}
