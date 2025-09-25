const std = @import("std");
const testing = std.testing;
const crypto = std.crypto;
const Ed25519 = std.crypto.sign.Ed25519;

const paseto = @import("paseto.zig");
const utils = @import("utils.zig");
const rsa = @import("rsa/rsa.zig");

const TestRNG = utils.TestRNG;

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
    const pri_key_seed = try std.fmt.hexToBytes(&buf3, secret_key_seed);

    var seed: [paseto.Ed25519.KeyPair.seed_length]u8 = undefined;
    @memcpy(seed[0..], pri_key_seed);

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

// ======================================

test "V3Local EncryptDecrypt" {
    const key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

    var buf: [32]u8 = undefined;
    const k = try std.fmt.hexToBytes(&buf, key);

    const m = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const f = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
    const i = "{\"test-vector\":\"4-S-3\"}";

    const alloc = testing.allocator;

    var e = paseto.V3Local.init(alloc);
    defer e.deinit();

    try e.withMessage(m);
    try e.withFooter(f);
    try e.withImplicit(i);

    const token = try e.encode(crypto.random, k);
    defer alloc.free(token);

    // ==================

    var p = paseto.V3Local.init(alloc);
    defer p.deinit();

    try p.withImplicit(i);

    try p.decode(token, k);

    try testing.expectFmt(m, "{s}", .{p.message});
    try testing.expectFmt(f, "{s}", .{p.footer});
    try testing.expectFmt(i, "{s}", .{p.implicit});
}

fn testV3LocalVectorT(comptime nonce: []const u8) type {
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

            var e = paseto.V3Local.init(alloc);
            defer e.deinit();

            try e.withMessage(payload);
            try e.withFooter(footer);
            try e.withImplicit(implicit_assertion);

            const encoded = try e.encode(test_rng, k);
            defer alloc.free(encoded);

            try testing.expectFmt(token, "{s}", .{encoded});

            // ==================

            var p = paseto.V3Local.init(alloc);
            defer p.deinit();

            try p.withImplicit(implicit_assertion);

            try p.decode(token, k);

            try testing.expectFmt(payload, "{s}", .{p.message});
        }
    };
}

test "v3 LocalVector" {
    // https://github.com/paseto-standard/test-vectors/blob/master/v3.json

    // 4-E-1
    try testV3LocalVectorT("0000000000000000000000000000000000000000000000000000000000000000").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAsRm2EsD6yBoZYn6cpVZNzSJOhSDN-sRaWjfLU-yn9OJH1J_B8GKtOQ9gSQlb8yk9Iza7teRdkiR89ZFyvPPsVjjFiepFUVcMa-LP18zV77f_crJrVXWa5PDNRkCSeHfBBeg",
        "{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "",
        "",
    );
    // 4-E-2
    try testV3LocalVectorT("0000000000000000000000000000000000000000000000000000000000000000").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAqhWxBMDgyBoZYn6cpVZNzSJOhSDN-sRaWjfLU-yn9OJH1J_B8GKtOQ9gSQlb8yk9IzZfaZpReVpHlDSwfuygx1riVXYVs-UjcrG_apl9oz3jCVmmJbRuKn5ZfD8mHz2db0A",
        "{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "",
        "",
    );
    // 4-E-3
    try testV3LocalVectorT("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlxnt5xyhQjFJomwnt7WW_7r2VT0G704ifult011-TgLCyQ2X8imQhniG_hAQ4BydM",
        "{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "",
        "",
    );
    // 4-E-4
    try testV3LocalVectorT("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlBZa_gOpVj4gv0M9lV6Pwjp8JS_MmaZaTA1LLTULXybOBZ2S4xMbYqYmDRhh3IgEk",
        "{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "",
        "",
    );
    // 4-E-5
    try testV3LocalVectorT("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlkYSIbXOgVuIQL65UMdW9WcjOpmqvjqD40NNzed-XPqn1T3w-bJvitYpUJL_rmihc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
        "{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}",
        "",
    );
    // 4-E-6
    try testV3LocalVectorT("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJmSeEMphEWHiwtDKJftg41O1F8Hat-8kQ82ZIAMFqkx9q5VkWlxZke9ZzMBbb3Znfo.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
        "{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}",
        "",
    );
    // 4-E-7
    try testV3LocalVectorT("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJkzWACWAIoVa0bz7EWSBoTEnS8MvGBYHHo6t6mJunPrFR9JKXFCc0obwz5N-pxFLOc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
        "{\"data\":\"this is a secret message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}",
        "{\"test-vector\":\"3-E-7\"}",
    );
    // 4-E-8
    try testV3LocalVectorT("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJmZHSSKYR6AnPYJV6gpHtx6dLakIG_AOPhu8vKexNyrv5_1qoom6_NaPGecoiz6fR8.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
        "{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}",
        "{\"test-vector\":\"3-E-8\"}",
    );
    // 4-E-9
    try testV3LocalVectorT("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlk1nli0_wijTH_vCuRwckEDc82QWK8-lG2fT9wQF271sgbVRVPjm0LwMQZkvvamqU.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24",
        "{\"data\":\"this is a hidden message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "arbitrary-string-that-isn't-json",
        "{\"test-vector\":\"3-E-9\"}",
    );
}

// ======================================

test "V3Public EncryptDecrypt" {
    const m = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const f = "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}";
    const i = "{\"test-vector\":\"3-S-3\"}";

    const alloc = testing.allocator;

    const kp = paseto.EcdsaP384Sha384.KeyPair.generate();

    var e = paseto.V3Public.init(alloc);
    defer e.deinit();

    try e.withMessage(m);
    try e.withFooter(f);
    try e.withImplicit(i);

    const token = try e.encode(crypto.random, kp.secret_key);
    defer alloc.free(token);

    // ==================

    var p = paseto.V3Public.init(alloc);
    defer p.deinit();

    try p.withImplicit(i);

    try p.decode(token, kp.public_key);

    try testing.expectFmt(m, "{s}", .{p.message});
    try testing.expectFmt(f, "{s}", .{p.footer});
    try testing.expectFmt(i, "{s}", .{p.implicit});
}

fn testV3PublicVector(
    public_key: []const u8,
    secret_key: []const u8,
    token: []const u8,
    payload: []const u8,
    footer: []const u8,
    implicit_assertion: []const u8,
) !void {
    var buf3: [48]u8 = undefined;
    const pri_key_seed = try std.fmt.hexToBytes(&buf3, secret_key);

    var pri_bytes: [paseto.EcdsaP384Sha384.SecretKey.encoded_length]u8 = undefined;
    @memcpy(pri_bytes[0..], pri_key_seed);

    const pri = try paseto.EcdsaP384Sha384.SecretKey.fromBytes(pri_bytes);
    const kp = try paseto.EcdsaP384Sha384.KeyPair.fromSecretKey(pri);

    const sk = kp.secret_key;
    const pk = kp.public_key;

    try testing.expectFmt(secret_key, "{x}", .{sk.toBytes()});
    try testing.expectFmt(public_key, "{x}", .{pk.toCompressedSec1()});

    // =====================

    const alloc = testing.allocator;

    var e = paseto.V3Public.init(alloc);
    defer e.deinit();

    try e.withMessage(payload);
    try e.withFooter(footer);
    try e.withImplicit(implicit_assertion);

    const encoded = try e.encode(crypto.random, sk);
    defer alloc.free(encoded);

    try testing.expectEqual(true, encoded.len > 0);

    // ==================

    var p = paseto.V3Public.init(alloc);
    defer p.deinit();

    try p.withImplicit(implicit_assertion);

    try p.decode(token, pk);

    try testing.expectFmt(payload, "{s}", .{p.message});
}

test "v3 PublicVector" {
    // https://github.com/paseto-standard/test-vectors/blob/master/v3.json

    // 3-S-1
    try testV3PublicVector(
        "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb",
        "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96",
        "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9qqEwwrKHKi5lJ7b9MBKc0G4MGZy0ptUiMv3lAUAaz-JY_zjoqBSIxMxhfAoeNYiSyvfUErj76KOPWm1OeNnBPkTSespeSXDGaDfxeIrl3bRrPEIy7tLwLAIsRzsXkfph",
        "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "",
        "",
    );
    // 3-S-2
    try testV3PublicVector(
        "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb",
        "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96",
        "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9ZWrbGZ6L0MDK72skosUaS0Dz7wJ_2bMcM6tOxFuCasO9GhwHrvvchqgXQNLQQyWzGC2wkr-VKII71AvkLpC8tJOrzJV1cap9NRwoFzbcXjzMZyxQ0wkshxZxx8ImmNWP.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9",
        "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}",
        "",
    );
    // 3-S-3
    try testV3PublicVector(
        "02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb",
        "20347609607477aca8fbfbc5e6218455f3199669792ef8b466faa87bdc67798144c848dd03661eed5ac62461340cea96",
        "v3.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ94SjWIbjmS7715GjLSnHnpJrC9Z-cnwK45dmvnVvCRQDCCKAXaKEopTajX0DKYx1Xqr6gcTdfqscLCAbiB4eOW9jlt-oNqdG8TjsYEi6aloBfTzF1DXff_45tFlnBukEX.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9",
        "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}",
        "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}",
        "{\"test-vector\":\"3-S-3\"}",
    );
}

test "V3Public EncryptDecrypt with der key" {
    const m = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const f = "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}";
    const i = "{\"test-vector\":\"3-S-3\"}";

    const alloc = testing.allocator;

    const prikey = "MIGkAgEBBDDqWgdCzllebram3uEH+cbKAjsu5xHwL/kZa97cfTJVdZ4j+IMj99PHZkdfxli2vo2gBwYFK4EEACKhZANiAAS5Zzmt6BAsk5mfpCqYBXK3PVy8Vgvkof3+8XLoRpq04PjnwLtdtY/M5pnMxsyWbIRbZHtB8Qkeb71EF+jg7WAtb9B013H1rvlbtVXu0uCmUE3J8hQ3EqY6ugmwqUUhi0M=";
    const pubkey = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuWc5regQLJOZn6QqmAVytz1cvFYL5KH9/vFy6EaatOD458C7XbWPzOaZzMbMlmyEW2R7QfEJHm+9RBfo4O1gLW/QdNdx9a75W7VV7tLgplBNyfIUNxKmOroJsKlFIYtD";

    const prikey_bytes = try utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try paseto.parser.ParseEcdsaP384Sha384Der.parseSecretKeyDer(prikey_bytes);
    const public_key = try paseto.parser.ParseEcdsaP384Sha384Der.parsePublicKeyDer(pubkey_bytes);

    var e = paseto.V3Public.init(alloc);
    defer e.deinit();

    try e.withMessage(m);
    try e.withFooter(f);
    try e.withImplicit(i);

    const token = try e.encode(crypto.random, secret_key);
    defer alloc.free(token);

    // ==================

    var p = paseto.V3Public.init(alloc);
    defer p.deinit();

    try p.withImplicit(i);

    try p.decode(token, public_key);

    try testing.expectFmt(m, "{s}", .{p.message});
    try testing.expectFmt(f, "{s}", .{p.footer});
    try testing.expectFmt(i, "{s}", .{p.implicit});
}

// ======================================

test "V2Local EncryptDecrypt" {
    const key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

    var buf: [32]u8 = undefined;
    const k = try std.fmt.hexToBytes(&buf, key);

    const m = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const f = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
    const i = "{\"test-vector\":\"2-E-3\"}";

    const alloc = testing.allocator;

    var e = paseto.V2Local.init(alloc);
    defer e.deinit();

    try e.withMessage(m);
    try e.withFooter(f);
    try e.withImplicit(i);

    const token = try e.encode(crypto.random, k);
    defer alloc.free(token);

    // ==================

    var p = paseto.V2Local.init(alloc);
    defer p.deinit();

    try p.withImplicit(i);

    try p.decode(token, k);

    try testing.expectFmt(m, "{s}", .{p.message});
    try testing.expectFmt(f, "{s}", .{p.footer});
    try testing.expectFmt(i, "{s}", .{p.implicit});
}

fn testV2LocalVectorT(comptime nonce: []const u8) type {
    return struct {
        fn testLocalVector(
            key: []const u8,
            token: []const u8,
            payload: []const u8,
            footer: []const u8,
        ) !void {
            var buf: [32]u8 = undefined;
            const k = try std.fmt.hexToBytes(&buf, key);

            const test_rng: std.Random = .{
                .ptr = undefined,
                .fillFn = TestRNG(nonce).fill,
            };

            const alloc = testing.allocator;

            var e = paseto.V2Local.init(alloc);
            defer e.deinit();

            try e.withMessage(payload);
            try e.withFooter(footer);

            const encoded = try e.encode(test_rng, k);
            defer alloc.free(encoded);

            try testing.expectFmt(token, "{s}", .{encoded});

            // ==================

            var p = paseto.V2Local.init(alloc);
            defer p.deinit();

            try p.decode(token, k);

            try testing.expectFmt(payload, "{s}", .{p.message});
        }
    };
}

test "v2 LocalVector" {
    const nullKey = "0000000000000000000000000000000000000000000000000000000000000000";
    const fullKey = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const symmetricKey = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

    const nonce = "000000000000000000000000000000000000000000000000";
    const nonce2 = "45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b";

    const footer = "Cuon Alpinus";
    const payload = "Love is stronger than hate or fear";

    try testV2LocalVectorT(nonce).testLocalVector(
        nullKey,
        "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNUtKpdy5KXjKfpSKrOlqQvQ",
        "",
        "",
    );
    try testV2LocalVectorT(nonce).testLocalVector(
        fullKey,
        "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNSOvpveyCsjPYfe9mtiJDVg",
        "",
        "",
    );
    try testV2LocalVectorT(nonce).testLocalVector(
        symmetricKey,
        "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNkIWACdHuLiJiW16f2GuGYA",
        "",
        "",
    );

    try testV2LocalVectorT(nonce).testLocalVector(
        nullKey,
        "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNfzz6yGkE4ZxojJAJwKLfvg.Q3VvbiBBbHBpbnVz",
        "",
        footer,
    );
    try testV2LocalVectorT(nonce).testLocalVector(
        fullKey,
        "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNJbTJxAGtEg4ZMXY9g2LSoQ.Q3VvbiBBbHBpbnVz",
        "",
        footer,
    );
    try testV2LocalVectorT(nonce).testLocalVector(
        symmetricKey,
        "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNreCcZAS0iGVlzdHjTf2ilg.Q3VvbiBBbHBpbnVz",
        "",
        footer,
    );

    try testV2LocalVectorT(nonce).testLocalVector(
        nullKey,
        "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSvu6cB-KuR4wR9uDMjd45cPiOF0zxb7rrtOB5tRcS7dWsFwY4ONEuL5sWeunqHC9jxU0",
        payload,
        "",
    );
    try testV2LocalVectorT(nonce).testLocalVector(
        fullKey,
        "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSjvSia2-chHyMi4LtHA8yFr1V7iZmKBWqzg5geEyNAAaD6xSEfxoET1xXqahe1jqmmPw",
        payload,
        "",
    );
    try testV2LocalVectorT(nonce).testLocalVector(
        symmetricKey,
        "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSXlvv8MsrNZs3vTSnGQG4qRM9ezDl880jFwknSA6JARj2qKhDHnlSHx1GSCizfcF019U",
        payload,
        "",
    );

    try testV2LocalVectorT(nonce2).testLocalVector(
        nullKey,
        "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvbcqXgWxM3vJGrJ9kWqquP61Xl7bz4ZEqN5XwH7xyzV0QqPIo0k52q5sWxUQ4LMBFFso.Q3VvbiBBbHBpbnVz",
        payload,
        footer,
    );
    try testV2LocalVectorT(nonce2).testLocalVector(
        fullKey,
        "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvZMW3MgUMFplQXsxcNlg2RX8LzFxAqj4qa2FwgrUdH4vYAXtCFrlGiLnk-cHHOWSUSaw.Q3VvbiBBbHBpbnVz",
        payload,
        footer,
    );
    try testV2LocalVectorT(nonce2).testLocalVector(
        symmetricKey,
        "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvl05z9GIX0cnol6UK94cfV77AXnShlUcNgpDR12FrQiurS8jxBRmvoIKmeMWC5wY9Y6w.Q3VvbiBBbHBpbnVz",
        payload,
        footer,
    );
}

// ======================================

test "V2Public EncryptDecrypt" {
    const m = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const f = "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}";
    const i = "{\"test-vector\":\"2-S-3\"}";

    const alloc = testing.allocator;

    const kp = paseto.Ed25519.KeyPair.generate();

    var e = paseto.V2Public.init(alloc);
    defer e.deinit();

    try e.withMessage(m);
    try e.withFooter(f);
    try e.withImplicit(i);

    const token = try e.encode(crypto.random, kp.secret_key);
    defer alloc.free(token);

    // ==================

    var p = paseto.V2Public.init(alloc);
    defer p.deinit();

    try p.withImplicit(i);

    try p.decode(token, kp.public_key);

    try testing.expectFmt(m, "{s}", .{p.message});
    try testing.expectFmt(f, "{s}", .{p.footer});
    try testing.expectFmt(i, "{s}", .{p.implicit});
}

fn testV2PublicVector(
    secret_key: []const u8,
    token: []const u8,
    payload: []const u8,
    footer: []const u8,
) !void {
    var buf: [64]u8 = undefined;
    const k_bytes = try std.fmt.hexToBytes(&buf, secret_key);

    var prikey_bytes: [Ed25519.SecretKey.encoded_length]u8 = undefined;
    @memcpy(prikey_bytes[0..], k_bytes);

    const prikey = try Ed25519.SecretKey.fromBytes(prikey_bytes);
    const kp = try Ed25519.KeyPair.fromSecretKey(prikey);
    const pubkey = kp.public_key;

    // =====================

    const alloc = testing.allocator;

    var e = paseto.V2Public.init(alloc);
    defer e.deinit();

    try e.withMessage(payload);
    try e.withFooter(footer);

    const encoded = try e.encode(crypto.random, prikey);
    defer alloc.free(encoded);

    try testing.expectFmt(token, "{s}", .{encoded});

    // ==================

    var p = paseto.V2Public.init(alloc);
    defer p.deinit();

    try p.decode(token, pubkey);

    try testing.expectFmt(payload, "{s}", .{p.message});
}

test "v2 PublicVector" {
    try testV2PublicVector(
        "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
        "v2.public.xnHHprS7sEyjP5vWpOvHjAP2f0HER7SWfPuehZ8QIctJRPTrlZLtRCk9_iNdugsrqJoGaO4k9cDBq3TOXu24AA",
        "",
        "",
    );
    try testV2PublicVector(
        "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
        "v2.public.Qf-w0RdU2SDGW_awMwbfC0Alf_nd3ibUdY3HigzU7tn_4MPMYIKAJk_J_yKYltxrGlxEdrWIqyfjW81njtRyDw.Q3VvbiBBbHBpbnVz",
        "",
        "Cuon Alpinus",
    );
    try testV2PublicVector(
        "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
        "v2.public.RnJhbmsgRGVuaXMgcm9ja3NBeHgns4TLYAoyD1OPHww0qfxHdTdzkKcyaE4_fBF2WuY1JNRW_yI8qRhZmNTaO19zRhki6YWRaKKlCZNCNrQM",
        "Frank Denis rocks",
        "",
    );

    try testV2PublicVector(
        "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
        "v2.public.RnJhbmsgRGVuaXMgcm9ja3qIOKf8zCok6-B5cmV3NmGJCD6y3J8fmbFY9KHau6-e9qUICrGlWX8zLo-EqzBFIT36WovQvbQZq4j6DcVfKCML",
        "Frank Denis rockz",
        "",
    );
    try testV2PublicVector(
        "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
        "v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0F.Q3VvbiBBbHBpbnVz",
        "Frank Denis rocks",
        "Cuon Alpinus",
    );

    try testV2PublicVector(
        "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
        "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifSUGY_L1YtOvo1JeNVAWQkOBILGSjtkX_9-g2pVPad7_SAyejb6Q2TDOvfCOpWYH5DaFeLOwwpTnaTXeg8YbUwI",
        "{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}",
        "",
    );
    try testV2PublicVector(
        "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2",
        "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifcMYjoUaEYXAtzTDwlcOlxdcZWIZp8qZga3jFS8JwdEjEvurZhs6AmTU3bRW5pB9fOQwm43rzmibZXcAkQ4AzQs.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz",
        "{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}",
        "Paragon Initiative Enterprises",
    );
}

test "V2Public EncryptDecrypt with der key" {
    const m = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const f = "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}";
    const i = "{\"test-vector\":\"2-S-3\"}";

    const alloc = testing.allocator;

    const prikey = "MC4CAQAwBQYDK2VwBCIEIE7YvvGJzvKQ3uZOQ6qAPkRsK7nkpmjPOaqsZKqrFQMw";
    const pubkey = "MCowBQYDK2VwAyEAgbbl7UO5W8ZMmOm+Kw9X2y9PyblBTDcZIRaR/kDFoA0=";

    const prikey_bytes = try utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try paseto.parser.ParseEddsaDer.parseSecretKeyDer(prikey_bytes);
    const public_key = try paseto.parser.ParseEddsaDer.parsePublicKeyDer(pubkey_bytes);

    var e = paseto.V2Public.init(alloc);
    defer e.deinit();

    try e.withMessage(m);
    try e.withFooter(f);
    try e.withImplicit(i);

    const token = try e.encode(crypto.random, secret_key);
    defer alloc.free(token);

    // ==================

    var p = paseto.V2Public.init(alloc);
    defer p.deinit();

    try p.withImplicit(i);

    try p.decode(token, public_key);

    try testing.expectFmt(m, "{s}", .{p.message});
    try testing.expectFmt(f, "{s}", .{p.footer});
    try testing.expectFmt(i, "{s}", .{p.implicit});
}

// ======================================

test "V1Local EncryptDecrypt" {
    const key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

    var buf: [32]u8 = undefined;
    const k = try std.fmt.hexToBytes(&buf, key);

    const m = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const f = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
    const i = "{\"test-vector\":\"2-E-3\"}";

    const alloc = testing.allocator;

    var e = paseto.V1Local.init(alloc);
    defer e.deinit();

    try e.withMessage(m);
    try e.withFooter(f);
    try e.withImplicit(i);

    const token = try e.encode(crypto.random, k);
    defer alloc.free(token);

    // ==================

    var p = paseto.V1Local.init(alloc);
    defer p.deinit();

    try p.withImplicit(i);

    try p.decode(token, k);

    try testing.expectFmt(m, "{s}", .{p.message});
    try testing.expectFmt(f, "{s}", .{p.footer});
    try testing.expectFmt(i, "{s}", .{p.implicit});
}

fn testV1LocalVectorT(comptime nonce: []const u8) type {
    return struct {
        fn testLocalVector(
            key: []const u8,
            token: []const u8,
            payload: []const u8,
            footer: []const u8,
        ) !void {
            var buf: [32]u8 = undefined;
            const k = try std.fmt.hexToBytes(&buf, key);

            const test_rng: std.Random = .{
                .ptr = undefined,
                .fillFn = TestRNG(nonce).fill,
            };

            const alloc = testing.allocator;

            var e = paseto.V1Local.init(alloc);
            defer e.deinit();

            try e.withMessage(payload);
            try e.withFooter(footer);

            const encoded = try e.encode(test_rng, k);
            defer alloc.free(encoded);

            try testing.expectFmt(token, "{s}", .{encoded});

            // ==================

            var p = paseto.V1Local.init(alloc);
            defer p.deinit();

            try p.decode(token, k);

            try testing.expectFmt(payload, "{s}", .{p.message});
        }
    };
}

test "v1 LocalVector" {
    const nullKey = "0000000000000000000000000000000000000000000000000000000000000000";
    const fullKey = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const symmetricKey = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

    const nonce = "0000000000000000000000000000000000000000000000000000000000000000";
    const nonce2 = "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2";

    const footer = "Cuon Alpinus";
    const payload = "Love is stronger than hate or fear";

    try testV1LocalVectorT(nonce).testLocalVector(
        nullKey,
        "v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTXyNMehtdOLJS_vq4YzYdaZ6vwItmpjx-Lt3AtVanBmiMyzFyqJMHCaWVMpEMUyxUg",
        "",
        "",
    );
    try testV1LocalVectorT(nonce).testLocalVector(
        fullKey,
        "v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTWgetvu2STfe7gxkDpAOk_IXGmBeea4tGW6HsoH12oKElAWap57-PQMopNurtEoEdk",
        "",
        "",
    );
    try testV1LocalVectorT(nonce).testLocalVector(
        symmetricKey,
        "v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTV8OmiMvoZgzer20TE8kb3R0QN9Ay-ICSkDD1-UDznTCdBiHX1fbb53wdB5ng9nCDY",
        "",
        "",
    );

    try testV1LocalVectorT(nonce).testLocalVector(
        nullKey,
        "v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTVhyXOB4vmrFm9GvbJdMZGArV5_10Kxwlv4qSb-MjRGgFzPg00-T2TCFdmc9BMvJAA.Q3VvbiBBbHBpbnVz",
        "",
        footer,
    );
    try testV1LocalVectorT(nonce).testLocalVector(
        fullKey,
        "v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTVna3s7WqUwfQaVM8ddnvjPkrWkYRquX58-_RgRQTnHn7hwGJwKT3H23ZDlioSiJeo.Q3VvbiBBbHBpbnVz",
        "",
        footer,
    );
    try testV1LocalVectorT(nonce).testLocalVector(
        symmetricKey,
        "v1.local.bB8u6Tj60uJL2RKYR0OCyiGMdds9g-EUs9Q2d3bRTTW9MRfGNyfC8vRpl8xsgnsWt-zHinI9bxLIVF0c6INWOv0_KYIYEaZjrtumY8cyo7M.Q3VvbiBBbHBpbnVz",
        "",
        footer,
    );

    try testV1LocalVectorT(nonce).testLocalVector(
        nullKey,
        "v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA45LtwQCqG8LYmNfBHIX-4Uxfm8KzaYAUUHqkxxv17MFxsEvk-Ex67g9P-z7EBFW09xxSt21Xm1ELB6pxErl4RE1gGtgvAm9tl3rW2-oy6qHlYx2",
        payload,
        "",
    );
    try testV1LocalVectorT(nonce).testLocalVector(
        fullKey,
        "v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA47lQ79wMmeM7sC4c0-BnsXzIteEQQBQpu_FyMznRnzYg4gN-6Kt50rXUxgPPfwDpOr3lUb5U16RzIGrMNemKy0gRhfKvAh1b8N57NKk93pZLpEz",
        payload,
        "",
    );
    try testV1LocalVectorT(nonce).testLocalVector(
        symmetricKey,
        "v1.local.N9n3wL3RJUckyWdg4kABZeMwaAfzNT3B64lhyx7QA47hvAicYf1zfZrxPrLeBFdbEKO3JRQdn3gjqVEkR1aXXttscmmZ6t48tfuuudETldFD_xbqID74_TIDO1JxDy7OFgYI_PehxzcapQ8t040Fgj9k",
        payload,
        "",
    );

    try testV1LocalVectorT(nonce2).testLocalVector(
        nullKey,
        "v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYbivwqsESBnr82_ZoMFFGzolJ6kpkOihkulB4K_JhfMHoFw4E9yCR6ltWX3e9MTNSud8mpBzZiwNXNbgXBLxF_Igb5Ixo_feIonmCucOXDlLVUT.Q3VvbiBBbHBpbnVz",
        payload,
        footer,
    );
    try testV1LocalVectorT(nonce2).testLocalVector(
        fullKey,
        "v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYZ8rQTA12SNb9cY8jVtVyikY2jj_tEBzY5O7GJsxb5MdQ6cMSnDz2uJGV20vhzVDgvkjdEcN9D44VaHid26qy1_1YlHjU6pmyTmJt8WT21LqzDl.Q3VvbiBBbHBpbnVz",
        payload,
        footer,
    );
    try testV1LocalVectorT(nonce2).testLocalVector(
        symmetricKey,
        "v1.local.rElw-WywOuwAqKC9Yao3YokSp7vx0YiUB9hLTnsVOYYTojmVaYumJSQt8aggtCaFKWyaodw5k-CUWhYKATopiabAl4OAmTxHCfm2E4NSPvrmMcmi8n-JcZ93HpcxC6rx_ps22vutv7iP7wf8QcSD1Mwx.Q3VvbiBBbHBpbnVz",
        payload,
        footer,
    );

    // https://github.com/paseto-standard/test-vectors/blob/master/v1.json

    // 1-E-1
    try testV1LocalVectorT("0000000000000000000000000000000000000000000000000000000000000000").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUVvn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcjd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6gos8fnfjJO8oKiqQMaiBP_Cqncmqw8",
        "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
        "",
    );
    // 1-E-2
    try testV1LocalVectorT("0000000000000000000000000000000000000000000000000000000000000000").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v1.local.w_NOpjgte4bX-2i1JAiTQzHoGUVOgc2yqKqsnYGmaPaCu_KWUkRGlCRnOvZZxeH4HTykY7AE_jkzSXAYBkQ1QnwvKS16uTXNfnmp8IRknY76I2m3S5qsM8klxWQQKFDuQHl8xXV0MwAoeFh9X6vbwIqrLlof3s4PMjRDwKsxYzkMr1RvfDI8emoPoW83q4Q60_xpHaw",
        "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
        "",
    );
    // 1-E-3
    try testV1LocalVectorT("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3syBYyjKIOeWnsFQB6Yef-1ov9rvqt7TmwONUHeJUYk4IK_JEdUeo_uFRqAIgHsiGCg",
        "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
        "",
    );
    // 1-E-4
    try testV1LocalVectorT("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvejdt2Srz_5Q0QG4oiz1gB_wmv4U5pifedaZbHXUTWXchFEi0etJ4u6tqgxZSklcec",
        "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
        "",
    );
    // 1-E-5
    try testV1LocalVectorT("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9cv39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs0aFc3ejjORmKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJZEWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
        "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
        "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}",
    );
    // 1-E-6
    try testV1LocalVectorT("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvcT2vnER6NrJ7xIowvFba6J4qMlFhBnYSxHEq9v9NlzcKsz1zscdjcAiXnEuCHyRSc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
        "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
        "{\"kid\":\"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo\"}",
    );
    // 1-E-9
    try testV1LocalVectorT("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2").testLocalVector(
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
        "v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbbpOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEqGNeeWXOyWWHoJQIe0d5nTdvdgNpe3vI21jV2YL7WVG5p63_JxxzLckBu9azQ0GlDMdPxNAxoyvmU1wbpSbRB9Iw4.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24",
        "{\"data\":\"this is a secret message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
        "arbitrary-string-that-isn't-json",
    );
}

// ======================================

test "V1Public EncryptDecrypt" {
    const m = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const f = "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}";
    const i = "{\"test-vector\":\"2-S-3\"}";

    const alloc = testing.allocator;

    const prikey = "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq";
    const pubkey = "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB";

    const prikey_bytes = try utils.base64Decode(alloc, prikey);
    const pubkey_bytes = try utils.base64Decode(alloc, pubkey);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const secret_key = try rsa.SecretKey.fromDer(prikey_bytes);
    const public_key = try rsa.PublicKey.fromDer(pubkey_bytes);

    var e = paseto.V1Public.init(alloc);
    defer e.deinit();

    try e.withMessage(m);
    try e.withFooter(f);
    try e.withImplicit(i);

    const token = try e.encode(crypto.random, secret_key);
    defer alloc.free(token);

    // ==================

    var p = paseto.V1Public.init(alloc);
    defer p.deinit();

    try p.withImplicit(i);

    try p.decode(token, public_key);

    try testing.expectFmt(m, "{s}", .{p.message});
    try testing.expectFmt(f, "{s}", .{p.footer});
    try testing.expectFmt(i, "{s}", .{p.implicit});
}

fn testV1PublicVector(
    secret_key: []const u8,
    public_key: []const u8,
    token: []const u8,
    payload: []const u8,
    footer: []const u8,
) !void {
    const alloc = testing.allocator;

    const prikey_bytes = try utils.base64Decode(alloc, secret_key);
    const pubkey_bytes = try utils.base64Decode(alloc, public_key);

    defer alloc.free(prikey_bytes);
    defer alloc.free(pubkey_bytes);

    const prikey = try rsa.SecretKey.fromDer(prikey_bytes);
    const pubkey = try rsa.PublicKey.fromDer(pubkey_bytes);

    // =====================

    var e = paseto.V1Public.init(alloc);
    defer e.deinit();

    try e.withMessage(payload);
    try e.withFooter(footer);

    const encoded = try e.encode(crypto.random, prikey);
    defer alloc.free(encoded);

    try testing.expectEqual(true, encoded.len > 0);

    // ==================

    var p = paseto.V1Public.init(alloc);
    defer p.deinit();

    try p.decode(token, pubkey);

    try testing.expectFmt(payload, "{s}", .{p.message});
}

test "v1 PublicVector" {
    try testV1PublicVector(
        "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq",
        "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB",
        "v1.public.UviYCKjE-iZqO16AMiXpH2JBmGqLZHco7ynTzr2magU5krprDDGa5Vy09_qrAnnQFSf5Qnwuos5W5e_fuLvVDxMO0WS0fQP_PfLrDBYf65FqGjBZ9SUdlHhEj5dqe1GNjDyawxqhRnGUb1WRBIfz8VhMEaPhW5NEayQ4sG0fO6pnTvOzSPnpCNGDGDvVE-Wmmv-_iyMHJCARZfW3TEYjasebte-AUXIYriREkJo9JjAELrKSUSIv5trGpRM0aI5h_WmYVYrg2SXmw61OKLxIU3un8dQNDFHCttBQ4Ak85RWTVhE6renMB7S5ONuTIRi7WNbloAGp9LimB0hCSvWx2g",
        "",
        "",
    );
    try testV1PublicVector(
        "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq",
        "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB",
        "v1.public.LtgW3XEzPD8Td2T4zP-5yJGFEG0OwpOUMoLa6z33dsiqpYm5r2gls8K89sMOXhOq3rhLXwtDsMYLmmGIFrIb5s7hkkQhuRpwWf3jfq_KkGWVOpCGKNI833R2hQJAaVTAFHgkdGjvAAG86OeAPKzZ7Jp3R_dVCqKDEIO8Wgj-B3c14LSqOCE4YR9QgyhHo9r9DWfH1RnrxMrLikj7j9_fVF5YKpA4x2vI9dJlPsfGmq93qVEXhS1JEWM7Vp6iPP17yQJWbOxygwLgH8TTcyumvkFHiUWFyBn2lW1ZvhXimxvbTQo0iic2EWRc9eAqbND-jT2NvX0W0jnFjFW0-mgwbA.Q3VvbiBBbHBpbnVz",
        "",
        "Cuon Alpinus",
    );
    try testV1PublicVector(
        "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq",
        "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB",
        "v1.public.RnJhbmsgRGVuaXMgcm9ja3PX5Y2ivH2g_-cdPy3FKSItJDFTtQ7biFpW8WTxXSxCNlXXR0pZXrVYRKtbML9XPxXCoXla00wsjHu_jEuB0frLPzeI5QShBsItFJwNttBN_8gwTmP6x2cihHTNpUozLquP9x_oihYsWZ_FghR6DKIcFfC3iNGtDpREV7cZtO4Yjdxdu2HvYf3mwt1KMRcwxFglKkBTD7O1ZJmfywCDJl0E2pHKWhpCAXC00mbiawsuUhDHxjL80FkW4JAXUXrW8BD3mR1gbSgHKfxGbNr_b7KphkFWjhJPwTem_uzdLkjsApb36KYVhlpyqNtG4nisuEi9ezvNshqmOjGtmZCdwhlz",
        "Frank Denis rocks",
        "",
    );

    try testV1PublicVector(
        "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq",
        "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB",
        "v1.public.RnJhbmsgRGVuaXMgcm9ja3qbyJ_sqh6c-4Ha_tZQ876EeKl1Ux9YYVKytcqLzc9AB6sNWXsXSAm_B7eM2okyjJVR1pKmuEWP2Rt__bSY3ureWBOaNSJZoBzVH7qaq_SP7eAbh8exH2Bmaw2rhdjeXmwhPrXsfUQwV-UG2CMnjcLPwTW6OtRU9Zr3Md0jyZRK8YCsIyu4sAmB5befIetswFNJVuQ5GW69dLa_R-hCmVH510tpK8O-42hKp_smBWZlyX1w7Wcj5YeNzpj2kYQYeUbmSkhY0gwN5ckI5sK9gFAuH7kYajcbFMLf3tbJzNnemzgBZl43g9v3KFPwdq-pq3jhrj14bVqtydaO5jU0luvx",
        "Frank Denis rockz",
        "",
    );
    try testV1PublicVector(
        "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq",
        "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB",
        "v1.public.RnJhbmsgRGVuaXMgcm9ja3M_dM236YO68eRSQsiABNRZ9B5QD4UrNZo0iQDohVvN8eWV9ZZKQ7m9rHfoRPrVeanLsgiCuiUr1z_Qxoa8OGTFWm2hhG9SKX8Pnt8WTeciUJt0Yf-_0KqipfPjWe74ZQTsNjU9z1HXMbqckOkgRIRbeSnrr5QjfRNo7u52WsJfE_pugcTZD96Yuby9fP5IT3qSW3GvsAcR3IJ6PQCGV7YizVLFX8PoSGRr3BD-l7eF4XadUjKfygqjxY56F9WD5vs-SWzSAaeYnGlMhmZpL-2JKNi44V2xAo6xwCtxNGvsdzozk1F8e4ZQidqGnDu8TrFxpHIkOA15NGLT6Mw6IO_c.Q3VvbiBBbHBpbnVz",
        "Frank Denis rocks",
        "Cuon Alpinus",
    );

    try testV1PublicVector(
        "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq",
        "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB",
        "v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifS6xZDRJfuOVZRc09QLd7sQ9h_I-pCvxLc6mBSwr2ZJHLhk8u8mhjrqAeUvYU0LaOthiXqfLurv-6-h4gap0VblMooVNBqNSHr8sKH6qAJupGYiRJFrrCsWBtDKhvwgj2s7CETGlm3Lm8DpbR--sYGYZNK8wkSCxFNz-lLVeUePwSO2JRXImtkZ4TcHedK6-BRgspEsThDkP0fqKfqfLfpShyS1VYVUqtyDxZd25YEBi0FLAPxeB1sSAYLtqkMLe2gWmmCbSdCS2t478imrJ_5RrZ3nv3Za145zFmFC0yuMrrYqvYGtWG1DhjCL8W9Z1pmgWKPwhrorc8cxIMzzsrHc",
        "{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}",
        "",
    );
    try testV1PublicVector(
        "MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIBAQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQG3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGjZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazKrtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvabDDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/njxIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNqibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjtu0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlghFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bgt1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+jrAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O998BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86EunfdPuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5WK3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aVbbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0KcnckbmDgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dncdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jpdbL83Fbq",
        "MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB",
        "v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwaXJlcyI6IjIwMTktMDEtMDFUMDA6MDA6MDArMDA6MDAifbxBICrgInL7N0u-SoHZnWppFjDJFj7NHTxwiSAONyGXfqVsRMzKKvcjBnaC2j1hxNj7dY8nVIUvDa7QbHpeie8XRGEuNFola-DOBceFLuFlHHAM8MbSe1WyeEkUkSO5xFtj-B6U-APU3E7-GIuVsdJ3Pjv3nZTvvYdx-SQl91feh9g_mSYeEFb1aUPGmtMvPurggZsmKi-IeqnC8fDPtfnmf_x96mPShuLLxgRFEocQ1IZ-Qstsvz_KrRGlHFcIHXjsb50E_tU8Cuo4kp-PAukf2Q4tVokQMYL_eF4CfPCZt88lOV8dXc6cRpDhpPXQv8o2aWHv-Riw1Zncowcbii8.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz",
        "{\"data\":\"this is a signed message\",\"expires\":\"2019-01-01T00:00:00+00:00\"}",
        "Paragon Initiative Enterprises",
    );

    // https://github.com/paseto-standard/test-vectors/blob/master/v1.json

    // 1-S-1
    try testV1PublicVector(
        "MIIEowIBAAKCAQEAyaTgTt53ph3p5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd74MSh/uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW+gmLbgYO/SZYfWF/M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5IpNxkRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6alUyhKC1+1w/FW6HWcp/JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQABAoIBAF22jLDa34yKdns3qfd7to+C3D5hRzAcMn6Azvf9qc+VybEI6RnjTHxDZWK5EajSP4/sQ15e8ivUk0JoWdJ53feL+hnQvwsab28gghSghrxM2kGwGA1XgO+SVawqJt8SjvE+Q+//01ZKK0OyA0cDJjX3L9RoPUN/moMeAPFw0hqkFEhm72GSVCEY1eY+cOXmL3icxnsnlUD//SS9q33RxF2y5oiW1edqcRqhW/7L1yYMbxHFUcxWh8WUwjn1AAhoCOUzF8ZB+0X/PPh+1nYoq6xwqL0ZKDwrQ8SDhW/rNDLeO9gic5rl7EetRQRbFvsZ40AdsX2wU+lWFUkB42AjuoECgYEA5z/CXqDFfZ8MXCPAOeui8y5HNDtu30aR+HOXsBDnRI8huXsGND04FfmXR7nkghr08fFVDmE4PeKUk810YJb+IAJo8wrOZ0682n6yEMO58omqKin+iIUVrPXLSLo5CChrqw2J4vgzolzPw3N5I8FJdLomb9FkrV84H+IviPIylyECgYEA3znwAG29QX6ATEfFpGVOcogorHCntd4niaWCq5ne5sFL+EwLeVc1zD9yj1axcDelICDZxCZynU7kDnrQcFkT0bjH/gC8Jk3v7XT9l1UDDqC1b7rm/X5wFIZ/rmNa1rVZhL1o/tKx5tvM2syJ1q95v7NdygFIEIW+qbIKbc6Wz0MCgYBsUZdQD+qx/xAhELX364I2epTryHMUrs+tGygQVrqdiJX5dcDgM1TUJkdQV6jLsKjPs4Vt6OgZRMrnuLMsk02R3M8gGQ25ok4f4nyyEZxGGWnVujn55KzUiYWhGWmhgp18UCkoYa59/Q9ss+gocV9hB9j9Q43vD80QUjiF4z0DQQKBgC7XQX1VibkMim93QAnXGDcAS0ij+w02qKVBjcHkb9mMBhz8GAxGOIu7ZJafYmxhwMyVGB0I1FQeEczYCJUKnBYN6Clsjg6bnBT/z5bJx/Jx1qCzX3Uh6vLjpjc5sf4L39Tyye1u2NXQmZPwB5x9BdcsFConSq/s4K1LJtUT3KFxAoGBANGcQ8nObi3m4wROyKrkCWcWxFFMnpwxv0pW727Hn9wuaOs4UbesCnwmpcMTfzGUDuzYXCtAq2pJl64HG6wsdkWmjBTJEpm6b9ibOBN3qFV2zQ0HyyKlMWxIuVSj9gOo61hF7UH9XB6R4HRdlpBOuIbgAWZ46dkj9/HM9ovdP0Iy",
        "MIIBCgKCAQEAyaTgTt53ph3p5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd74MSh/uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW+gmLbgYO/SZYfWF/M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5IpNxkRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6alUyhKC1+1w/FW6HWcp/JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQAB",
        "v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9sBTIb0J_4misAuYc4-6P5iR1rQighzktpXhJ8gtrrp2MqSSDkbb8q5WZh3FhUYuW_rg2X8aflDlTWKAqJkM3otjYwtmfwfOhRyykxRL2AfmIika_A-_MaLp9F0iw4S1JetQQDV8GUHjosd87TZ20lT2JQLhxKjBNJSwWue8ucGhTgJcpOhXcthqaz7a2yudGyd0layzeWziBhdQpoBR6ryTdtIQX54hP59k3XCIxuYbB9qJMpixiPAEKBcjHT74sA-uukug9VgKO7heWHwJL4Rl9ad21xyNwaxAnwAJ7C0fN5oGv8Rl0dF11b3tRmsmbDoIokIM0Dba29x_T3YzOyg.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9",
        "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
        "",
    );
    // 1-S-2
    try testV1PublicVector(
        "MIIEowIBAAKCAQEAyaTgTt53ph3p5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd74MSh/uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW+gmLbgYO/SZYfWF/M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5IpNxkRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6alUyhKC1+1w/FW6HWcp/JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQABAoIBAF22jLDa34yKdns3qfd7to+C3D5hRzAcMn6Azvf9qc+VybEI6RnjTHxDZWK5EajSP4/sQ15e8ivUk0JoWdJ53feL+hnQvwsab28gghSghrxM2kGwGA1XgO+SVawqJt8SjvE+Q+//01ZKK0OyA0cDJjX3L9RoPUN/moMeAPFw0hqkFEhm72GSVCEY1eY+cOXmL3icxnsnlUD//SS9q33RxF2y5oiW1edqcRqhW/7L1yYMbxHFUcxWh8WUwjn1AAhoCOUzF8ZB+0X/PPh+1nYoq6xwqL0ZKDwrQ8SDhW/rNDLeO9gic5rl7EetRQRbFvsZ40AdsX2wU+lWFUkB42AjuoECgYEA5z/CXqDFfZ8MXCPAOeui8y5HNDtu30aR+HOXsBDnRI8huXsGND04FfmXR7nkghr08fFVDmE4PeKUk810YJb+IAJo8wrOZ0682n6yEMO58omqKin+iIUVrPXLSLo5CChrqw2J4vgzolzPw3N5I8FJdLomb9FkrV84H+IviPIylyECgYEA3znwAG29QX6ATEfFpGVOcogorHCntd4niaWCq5ne5sFL+EwLeVc1zD9yj1axcDelICDZxCZynU7kDnrQcFkT0bjH/gC8Jk3v7XT9l1UDDqC1b7rm/X5wFIZ/rmNa1rVZhL1o/tKx5tvM2syJ1q95v7NdygFIEIW+qbIKbc6Wz0MCgYBsUZdQD+qx/xAhELX364I2epTryHMUrs+tGygQVrqdiJX5dcDgM1TUJkdQV6jLsKjPs4Vt6OgZRMrnuLMsk02R3M8gGQ25ok4f4nyyEZxGGWnVujn55KzUiYWhGWmhgp18UCkoYa59/Q9ss+gocV9hB9j9Q43vD80QUjiF4z0DQQKBgC7XQX1VibkMim93QAnXGDcAS0ij+w02qKVBjcHkb9mMBhz8GAxGOIu7ZJafYmxhwMyVGB0I1FQeEczYCJUKnBYN6Clsjg6bnBT/z5bJx/Jx1qCzX3Uh6vLjpjc5sf4L39Tyye1u2NXQmZPwB5x9BdcsFConSq/s4K1LJtUT3KFxAoGBANGcQ8nObi3m4wROyKrkCWcWxFFMnpwxv0pW727Hn9wuaOs4UbesCnwmpcMTfzGUDuzYXCtAq2pJl64HG6wsdkWmjBTJEpm6b9ibOBN3qFV2zQ0HyyKlMWxIuVSj9gOo61hF7UH9XB6R4HRdlpBOuIbgAWZ46dkj9/HM9ovdP0Iy",
        "MIIBCgKCAQEAyaTgTt53ph3p5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd74MSh/uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW+gmLbgYO/SZYfWF/M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5IpNxkRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6alUyhKC1+1w/FW6HWcp/JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQAB",
        "v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9sBTIb0J_4misAuYc4-6P5iR1rQighzktpXhJ8gtrrp2MqSSDkbb8q5WZh3FhUYuW_rg2X8aflDlTWKAqJkM3otjYwtmfwfOhRyykxRL2AfmIika_A-_MaLp9F0iw4S1JetQQDV8GUHjosd87TZ20lT2JQLhxKjBNJSwWue8ucGhTgJcpOhXcthqaz7a2yudGyd0layzeWziBhdQpoBR6ryTdtIQX54hP59k3XCIxuYbB9qJMpixiPAEKBcjHT74sA-uukug9VgKO7heWHwJL4Rl9ad21xyNwaxAnwAJ7C0fN5oGv8Rl0dF11b3tRmsmbDoIokIM0Dba29x_T3YzOyg.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9",
        "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
        "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}",
    );
    // 1-S-3
    try testV1PublicVector(
        "MIIEowIBAAKCAQEAyaTgTt53ph3p5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd74MSh/uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW+gmLbgYO/SZYfWF/M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5IpNxkRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6alUyhKC1+1w/FW6HWcp/JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQABAoIBAF22jLDa34yKdns3qfd7to+C3D5hRzAcMn6Azvf9qc+VybEI6RnjTHxDZWK5EajSP4/sQ15e8ivUk0JoWdJ53feL+hnQvwsab28gghSghrxM2kGwGA1XgO+SVawqJt8SjvE+Q+//01ZKK0OyA0cDJjX3L9RoPUN/moMeAPFw0hqkFEhm72GSVCEY1eY+cOXmL3icxnsnlUD//SS9q33RxF2y5oiW1edqcRqhW/7L1yYMbxHFUcxWh8WUwjn1AAhoCOUzF8ZB+0X/PPh+1nYoq6xwqL0ZKDwrQ8SDhW/rNDLeO9gic5rl7EetRQRbFvsZ40AdsX2wU+lWFUkB42AjuoECgYEA5z/CXqDFfZ8MXCPAOeui8y5HNDtu30aR+HOXsBDnRI8huXsGND04FfmXR7nkghr08fFVDmE4PeKUk810YJb+IAJo8wrOZ0682n6yEMO58omqKin+iIUVrPXLSLo5CChrqw2J4vgzolzPw3N5I8FJdLomb9FkrV84H+IviPIylyECgYEA3znwAG29QX6ATEfFpGVOcogorHCntd4niaWCq5ne5sFL+EwLeVc1zD9yj1axcDelICDZxCZynU7kDnrQcFkT0bjH/gC8Jk3v7XT9l1UDDqC1b7rm/X5wFIZ/rmNa1rVZhL1o/tKx5tvM2syJ1q95v7NdygFIEIW+qbIKbc6Wz0MCgYBsUZdQD+qx/xAhELX364I2epTryHMUrs+tGygQVrqdiJX5dcDgM1TUJkdQV6jLsKjPs4Vt6OgZRMrnuLMsk02R3M8gGQ25ok4f4nyyEZxGGWnVujn55KzUiYWhGWmhgp18UCkoYa59/Q9ss+gocV9hB9j9Q43vD80QUjiF4z0DQQKBgC7XQX1VibkMim93QAnXGDcAS0ij+w02qKVBjcHkb9mMBhz8GAxGOIu7ZJafYmxhwMyVGB0I1FQeEczYCJUKnBYN6Clsjg6bnBT/z5bJx/Jx1qCzX3Uh6vLjpjc5sf4L39Tyye1u2NXQmZPwB5x9BdcsFConSq/s4K1LJtUT3KFxAoGBANGcQ8nObi3m4wROyKrkCWcWxFFMnpwxv0pW727Hn9wuaOs4UbesCnwmpcMTfzGUDuzYXCtAq2pJl64HG6wsdkWmjBTJEpm6b9ibOBN3qFV2zQ0HyyKlMWxIuVSj9gOo61hF7UH9XB6R4HRdlpBOuIbgAWZ46dkj9/HM9ovdP0Iy",
        "MIIBCgKCAQEAyaTgTt53ph3p5GHgwoGWwz5hRfWXSQA08NCOwe0FEgALWos9GCjNFCd723nCHxBtN1qd74MSh/uN88JPIbwxKheDp4kxo4YMN5trPaF0e9G6Bj1N02HnanxFLW+gmLbgYO/SZYfWF/M8yLBcu5Y1Ot0ZxDDDXS9wIQTtBE0ne3YbxgZJAZTU5XqyQ1DxdzYyC5lF6yBaR5UQtCYTnXAApVRuUI2Sd6L1E2vl9bSBumZ5IpNxkRnAwIMjeTJB/0AIELh0mE5vwdihOCbdV6alUyhKC1+1w/FW6HWcp/JG1kKC8DPIidZ78Bbqv9YFzkAbNni5eSBOsXVBKG78Zsc8owIDAQAB",
        "v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9sBTIb0J_4misAuYc4-6P5iR1rQighzktpXhJ8gtrrp2MqSSDkbb8q5WZh3FhUYuW_rg2X8aflDlTWKAqJkM3otjYwtmfwfOhRyykxRL2AfmIika_A-_MaLp9F0iw4S1JetQQDV8GUHjosd87TZ20lT2JQLhxKjBNJSwWue8ucGhTgJcpOhXcthqaz7a2yudGyd0layzeWziBhdQpoBR6ryTdtIQX54hP59k3XCIxuYbB9qJMpixiPAEKBcjHT74sA-uukug9VgKO7heWHwJL4Rl9ad21xyNwaxAnwAJ7C0fN5oGv8Rl0dF11b3tRmsmbDoIokIM0Dba29x_T3YzOyg.eyJraWQiOiJkWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVxbiJ9",
        "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}",
        "{\"kid\":\"dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn\"}",
        // "discarded-anyway",
    );
}
