const std = @import("std");
const json = std.json;
const time = std.time;
const testing = std.testing;
const Allocator = std.mem.Allocator;

const utils = @import("utils.zig");

pub const Token = struct {
    raw: []const u8 = "",
    header: []const u8 = "",
    claims: []const u8 = "",
    footer: []const u8 = "",
    alloc: Allocator,

    const Self = @This();

    pub fn init(alloc: Allocator) Self {
        return .{
            .alloc = alloc,
        };
    }

    pub fn deinit(self: *Self) void {
        self.alloc.free(self.raw);
        self.alloc.free(self.header);
        self.alloc.free(self.claims);
        self.alloc.free(self.footer);
    }

    pub fn withHeader(self: *Self, header: []const u8) !void {
        self.header = try self.alloc.dupe(u8, header);
    }

    pub fn withClaims(self: *Self, claims: []const u8) !void {
        self.claims = try self.alloc.dupe(u8, claims);
    }

    pub fn setClaims(self: *Self, claims: anytype) !void {
        self.claims = try utils.jsonEncode(self.alloc, claims);
    }

    pub fn withFooter(self: *Self, footer: []const u8) !void {
        self.footer = try self.alloc.dupe(u8, footer);
    }

    pub fn setFooter(self: *Self, footer: anytype) !void {
        self.footer = try utils.jsonEncode(self.alloc, footer);
    }

    pub fn encode(self: *Self) ![]const u8 {
        var buf = try std.ArrayList(u8).initCapacity(self.alloc, 0);
        defer buf.deinit(self.alloc);

        try buf.appendSlice(self.alloc, self.header[0..]);

        const claims = try utils.base64UrlEncode(self.alloc, self.claims);
        try buf.append(self.alloc, '.');
        try buf.appendSlice(self.alloc, claims[0..]);

        defer self.alloc.free(claims);

        if (self.footer.len > 0) {
            const footer = try utils.base64UrlEncode(self.alloc, self.footer);
            try buf.append(self.alloc, '.');
            try buf.appendSlice(self.alloc, footer[0..]);

            defer self.alloc.free(footer);
        }

        return buf.toOwnedSlice(self.alloc);
    }

    pub fn parse(self: *Self, token_string: []const u8) void {
        self.raw = self.alloc.dupe(u8, token_string) catch "";
        self.header = "";
        self.claims = "";
        self.footer = "";

        if (token_string.len == 0) {
            return;
        }

        var header_ver: []const u8 = undefined;
        var header_type: []const u8 = undefined;

        var it = std.mem.splitScalar(u8, token_string, '.');
        if (it.next()) |pair| {
            header_ver = pair;
        }
        if (it.next()) |pair| {
            header_type = pair;
        }

        self.header = std.mem.join(self.alloc, ".", &[_][]const u8{ header_ver, header_type }) catch "";

        if (it.next()) |pair| {
            self.claims = utils.base64UrlDecode(self.alloc, pair) catch "";
        }
        if (it.next()) |pair| {
            self.footer = utils.base64UrlDecode(self.alloc, pair) catch "";
        }
    }

    pub fn getRaw(self: *Self) ![]const u8 {
        return self.alloc.dupe(u8, self.raw);
    }

    pub fn getPartCount(self: *Self) usize {
        const count = std.mem.count(u8, self.raw, ".");
        return count + 1;
    }

    pub fn getHeader(self: *Self) ![]const u8 {
        return self.alloc.dupe(u8, self.header);
    }

    pub fn getClaims(self: *Self) !json.Parsed(json.Value) {
        return utils.jsonDecode(self.alloc, self.claims);
    }

    pub fn getClaimsT(self: *Self, comptime T: type) !json.Parsed(T) {
        return utils.jsonDecodeT(T, self.alloc, self.claims);
    }

    pub fn getFooter(self: *Self) !json.Parsed(json.Value) {
        return utils.jsonDecode(self.alloc, self.footer);
    }

    pub fn getFooterT(self: *Self, comptime T: type) !json.Parsed(T) {
        return utils.jsonDecodeT(T, self.alloc, self.footer);
    }
};

test "Token" {
    const alloc = testing.allocator;

    const header = "v4.local";
    const claims = .{
        .aud = "example.com",
        .iat = "foo",
    };
    const footer = .{
        .bar = "foo",
    };

    const check = "v4.local.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.eyJiYXIiOiJmb28ifQ";

    var token = Token.init(alloc);
    try token.withHeader(header);
    try token.setClaims(claims);
    try token.setFooter(footer);

    defer token.deinit();

    const res1 = try token.encode();
    defer alloc.free(res1);
    try testing.expectEqualStrings(check, res1);

    // ====================

    // pub const ObjectMap = StringArrayHashMap(Value);
    // pub const Array = ArrayList(Value);
    // pub const json.Value = union(enum) {
    //     null,
    //     bool: bool,
    //     integer: i64,
    //     float: f64,
    //     number_string: []const u8,
    //     string: []const u8,
    //     array: Array,
    //     object: ObjectMap,
    // }

    var token2 = Token.init(alloc);
    token2.parse(check);

    defer token2.deinit();

    const header2 = try token2.getHeader();
    defer alloc.free(header2);
    try testing.expectEqualStrings(header, header2);

    const claims2 = try token2.getClaims();
    defer claims2.deinit();
    try testing.expectEqualStrings(claims.aud, claims2.value.object.get("aud").?.string);
    try testing.expectEqualStrings(claims.iat, claims2.value.object.get("iat").?.string);

    const footer2 = try token2.getFooter();
    defer footer2.deinit();
    try testing.expectEqualStrings(footer.bar, footer2.value.object.get("bar").?.string);

    const partCount = token2.getPartCount();
    try testing.expectEqual(4, partCount);

    // ====================

    const check3 = "v4.local.eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9";

    var token6 = Token.init(alloc);
    token6.parse(check3);

    defer token6.deinit();

    const sig61 = try token6.getRaw();
    defer alloc.free(sig61);
    try testing.expectEqualStrings(check3, sig61);

    const partCount6 = token6.getPartCount();
    try testing.expectEqual(3, partCount6);
}

test "Token 2" {
    const alloc = testing.allocator;

    const header = "v4.local";
    const claims = .{
        .aud = "example.com",
        .iat = "foo",
    };
    const footer = "test-footer";

    const check1 = "v4.local.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.dGVzdC1mb290ZXI";

    var token = Token.init(alloc);
    try token.withHeader(header);
    try token.setClaims(claims);
    try token.withFooter(footer);

    defer token.deinit();

    const res1 = try token.encode();
    defer alloc.free(res1);
    try testing.expectEqualStrings(check1, res1);

    // ======

    var token2 = Token.init(alloc);
    try token2.withHeader("ase123");
    try token2.withClaims("tyh78");
    try token2.withFooter("qwe");

    defer token2.deinit();

    try testing.expectEqualStrings("ase123", token2.header);
    try testing.expectEqualStrings("tyh78", token2.claims);
    try testing.expectEqualStrings("qwe", token2.footer);
}

test "Token 3" {
    const alloc = testing.allocator;

    const header = "v4.local";
    const claims = .{
        .aud = "example.com",
        .iat = "foo",
    };
    const footer = .{
        .bar = "foo",
    };

    const check1 = "v4.local.eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyJ9.eyJiYXIiOiJmb28ifQ";

    var token = Token.init(alloc);
    try token.withHeader(header);
    try token.setClaims(claims);
    try token.setFooter(footer);

    defer token.deinit();

    const res1 = try token.encode();
    defer alloc.free(res1);
    try testing.expectEqualStrings(check1, res1);

    // ================

    var token2 = Token.init(alloc);
    token2.parse(check1);

    defer token2.deinit();

    const claimsT = struct {
        aud: []const u8,
        iat: []const u8,
    };
    const claims3 = try token2.getClaimsT(claimsT);
    defer claims3.deinit();
    try testing.expectEqualStrings(claims.aud, claims3.value.aud);
    try testing.expectEqualStrings(claims.iat, claims3.value.iat);

    const footerT = struct {
        bar: []const u8,
    };
    const footer3 = try token2.getFooterT(footerT);
    defer footer3.deinit();
    try testing.expectEqualStrings(footer.bar, footer3.value.bar);

    const footer33 = try token2.getFooter();
    defer footer33.deinit();
    try testing.expectEqualStrings(footer.bar, footer33.value.object.get("bar").?.string);
}
