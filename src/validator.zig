const std = @import("std");
const json = std.json;
const time = std.time;
const testing = std.testing;

const utils = @import("utils.zig");

pub const Validator = struct {
    message: json.Parsed(json.Value),
    leeway: i64 = 0,

    const Self = @This();

    pub const Options = struct {
        leeway: i64 = 0,
    };

    pub fn init(message: json.Parsed(json.Value), options: Options) Self {
        return .{
            .message = message,
            .leeway = options.leeway,
        };
    }

    pub fn deinit(self: *Self) void {
        self.message.deinit();
    }

    pub fn withLeeway(self: *Self, leeway: i64) void {
        self.leeway = leeway;
    }

    pub fn isPermittedFor(self: *Self, audience: []const u8) bool {
        const message = self.message;

        if (message.value.object.get("aud")) |val| {
            if (val == .string) {
                if (utils.eq(audience, val.string)) {
                    return true;
                }
            }

            return false;
        }

        return false;
    }

    pub fn isIdentifiedBy(self: *Self, id: []const u8) bool {
        const message = self.message;

        if (message.value.object.get("jti")) |val| {
            if (val == .string) {
                if (utils.eq(id, val.string)) {
                    return true;
                }
            }

            return false;
        }

        return false;
    }

    pub fn isRelatedTo(self: *Self, subject: []const u8) bool {
        const message = self.message;

        if (message.value.object.get("sub")) |val| {
            if (val == .string) {
                if (utils.eq(subject, val.string)) {
                    return true;
                }
            }

            return false;
        }

        return false;
    }

    pub fn hasBeenIssuedBy(self: *Self, issuer: []const u8) bool {
        const message = self.message;

        if (message.value.object.get("iss")) |val| {
            if (val == .string) {
                if (utils.eq(issuer, val.string)) {
                    return true;
                }
            }

            return false;
        }

        return false;
    }

    pub fn hasBeenIssuedBefore(self: *Self, now: i64) bool {
        const message = self.message;

        if (message.value.object.get("iat")) |val| {
            if (val == .integer) {
                if (now + self.leeway >= val.integer) {
                    return true;
                }
            }

            return false;
        }

        return true;
    }

    pub fn isMinimumTimeBefore(self: *Self, now: i64) bool {
        const message = self.message;

        if (message.value.object.get("nbf")) |val| {
            if (val == .integer) {
                if (now + self.leeway >= val.integer) {
                    return true;
                }
            }

            return false;
        }

        return true;
    }

    pub fn isExpired(self: *Self, now: i64) bool {
        const message = self.message;

        if (message.value.object.get("exp")) |val| {
            if (val == .integer) {
                if (now - self.leeway < val.integer) {
                    return false;
                }
            }

            return true;
        }

        return false;
    }
};

test "Validator isExpired" {
    const alloc = testing.allocator;

    const check1 = "eyJleHAiOjE3Mzk4MTAzOTB9";
    const now = time.timestamp();

    const msg = try utils.base64UrlDecode(alloc, check1);
    defer alloc.free(msg);

    const msg_json = try utils.jsonDecode(alloc, msg);
    defer msg_json.deinit();

    var validator = Validator.init(msg_json, .{});
    // defer validator.deinit();

    const isExpired = validator.isExpired(now);

    try testing.expectEqual(true, isExpired);

    try testing.expectEqual(true, msg_json.value.object.get("exp").?.integer > 0);
}

test "Validator isMinimumTimeBefore" {
    const alloc = testing.allocator;

    const check1 = "eyJhdWQiOiJleGFtcGxlLmNvbSIsImlhdCI6ImZvbyIsIm5iZiI6MTczOTgxNjU0MH0";
    const now = time.timestamp();

    const msg = try utils.base64UrlDecode(alloc, check1);
    defer alloc.free(msg);

    const msg_json = try utils.jsonDecode(alloc, msg);
    defer msg_json.deinit();

    var validator = Validator.init(msg_json, .{});
    // defer validator.deinit();

    const isMinimumTimeBefore = validator.isMinimumTimeBefore(now);
    try testing.expectEqual(true, isMinimumTimeBefore);

    try testing.expectEqual(true, msg_json.value.object.get("nbf").?.integer > 0);
}

test "Validator" {
    const alloc = testing.allocator;

    const check1 = "eyJpc3MiOiJpc3MiLCJpYXQiOjE1Njc4NDIzODgsImV4cCI6MTc2Nzg0MjM4OCwiYXVkIjoiZXhhbXBsZS5jb20iLCJzdWIiOiJzdWIiLCJqdGkiOiJqdGkgcnJyIiwibmJmIjoxNTY3ODQyMzg4fQ";
    const now = time.timestamp();

    const msg = try utils.base64UrlDecode(alloc, check1);
    defer alloc.free(msg);

    const msg_json = try utils.jsonDecode(alloc, msg);
    defer msg_json.deinit();

    var validator = Validator.init(msg_json, .{});
    // defer validator.deinit();

    try testing.expectEqual(true, validator.hasBeenIssuedBy("iss"));
    try testing.expectEqual(true, validator.isRelatedTo("sub"));
    try testing.expectEqual(true, validator.isIdentifiedBy("jti rrr"));
    try testing.expectEqual(true, validator.isPermittedFor("example.com"));
    try testing.expectEqual(true, validator.hasBeenIssuedBefore(now));
    try testing.expectEqual(false, validator.isExpired(now));

    try testing.expectEqual(true, msg_json.value.object.get("nbf").?.integer > 0);

    try testing.expectEqual(1567842388, msg_json.value.object.get("iat").?.integer);
    try testing.expectEqual(1767842388, msg_json.value.object.get("exp").?.integer);
    try testing.expectEqual(1567842388, msg_json.value.object.get("nbf").?.integer);

    try testing.expectEqual(true, validator.hasBeenIssuedBefore(1567842389));
    try testing.expectEqual(true, validator.isMinimumTimeBefore(1567842389));
    try testing.expectEqual(true, validator.isExpired(1767842389));

    // ======

    var validator2 = Validator.init(msg_json, .{});
    // defer validator2.deinit();

    validator2.withLeeway(3);

    try testing.expectEqual(true, validator2.hasBeenIssuedBefore(1567842391));
    try testing.expectEqual(false, validator2.hasBeenIssuedBefore(1567842384));
    try testing.expectEqual(true, validator2.isMinimumTimeBefore(1567842391));
    try testing.expectEqual(false, validator2.isMinimumTimeBefore(1567842384));
    try testing.expectEqual(true, validator2.isExpired(1767842392));
    try testing.expectEqual(false, validator2.isExpired(1767842389));
}
