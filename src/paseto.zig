const std = @import("std");
const json = std.json;
const crypto = std.crypto;
const Allocator = std.mem.Allocator;

pub const utils = @import("utils.zig");
pub const Token = @import("token.zig").Token;

pub const v4_local = @import("v4_local.zig");

pub const V4Local = NewPaseto(v4_local.V4Local, []const u8, []const u8);

const Error = error{
    PasetoTokenInvalid,
    PasetoTokAlgoInvalid,
};

pub fn NewPaseto(comptime Encoder: type, comptime EncodeKeyType: type, comptime DecodeKeyType: type) type {
    return struct {
        message: []const u8 = "",
        footer: []const u8 = "",
        implicit: []const u8 = "",
        encoder: Encoder,
        alloc: Allocator,

        const Self = @This();

        pub fn init(alloc: Allocator) Self {
            return .{
                .encoder = Encoder.init(alloc),
                .alloc = alloc,
            };
        }

        pub fn deinit(self: *Self) void {
            self.alloc.free(self.message);
            self.alloc.free(self.footer);
            self.alloc.free(self.implicit);
        }

        pub fn alg(self: Self) []const u8 {
            return self.encoder.alg();
        }

        pub fn withMessage(self: *Self, message: []const u8) !void {
            self.message = try self.alloc.dupe(u8, message);
        }

        pub fn setMessage(self: *Self, message: anytype) !void {
            self.message = try utils.jsonEncode(self.alloc, message);
        }

        pub fn withFooter(self: *Self, footer: []const u8) !void {
            self.footer = try self.alloc.dupe(u8, footer);
        }

        pub fn setFooter(self: *Self, footer: anytype) !void {
            self.footer = try utils.jsonEncode(self.alloc, footer);
        }

        pub fn withImplicit(self: *Self, implicit: []const u8) !void {
            self.implicit = try self.alloc.dupe(u8, implicit);
        }

        pub fn setImplicit(self: *Self, implicit: anytype) !void {
            self.implicit = try utils.jsonEncode(self.alloc, implicit);
        }

        pub fn getMessage(self: *Self) !json.Parsed(json.Value) {
            return utils.jsonDecode(self.alloc, self.message);
        }

        pub fn getMessageT(self: *Self, comptime T: type) !json.Parsed(T) {
            return utils.jsonDecodeT(T, self.alloc, self.message);
        }

        pub fn getFooter(self: *Self) !json.Parsed(json.Value) {
            return utils.jsonDecode(self.alloc, self.footer);
        }

        pub fn getFooterT(self: *Self, comptime T: type) !json.Parsed(T) {
            return utils.jsonDecodeT(T, self.alloc, self.footer);
        }

        pub fn getImplicit(self: *Self) !json.Parsed(json.Value) {
            return utils.jsonDecode(self.alloc, self.implicit);
        }

        pub fn getImplicitT(self: *Self, comptime T: type) !json.Parsed(T) {
            return utils.jsonDecodeT(T, self.alloc, self.implicit);
        }

        // encode token
        pub fn encode(self: *Self, r: std.Random, encode_key: EncodeKeyType) ![]const u8 {
            const encoded = try self.encoder.encode(r, self.message, encode_key, self.footer, self.implicit);
            defer self.alloc.free(encoded);

            var t = Token.init(self.alloc);
            try t.withHeader(self.encoder.alg());
            try t.withClaims(encoded);
            try t.withFooter(self.footer);

            defer t.deinit();

            const encoded_string = try t.encode();

            return encoded_string;
        }

        // decode token
        pub fn decode(self: *Self, token_string: []const u8, decode_key: DecodeKeyType) !void {
            var t = try self.parseToken(token_string);
            defer t.deinit();

            try self.parse(t, decode_key);
        }

        // parse token
        pub fn parse(self: *Self, token: Token, decode_key: DecodeKeyType) !void {
            const decoded = try self.encoder.decode(token.claims, decode_key, token.footer, self.implicit);

            self.alloc.free(self.message);
            self.alloc.free(self.footer);

            self.message = decoded;
            self.footer = try self.alloc.dupe(u8, token.footer);
        }

        // parse token and return Token struct
        pub fn parseToken(self: *Self, token_string: []const u8) !Token {
            var t = Token.init(self.alloc);
            t.parse(token_string);

            if (t.getPartCount() < 3) {
                defer t.deinit();

                return Error.PasetoTokenInvalid;
            }

            const header = try t.getHeader();
            defer self.alloc.free(header);

            if (!utils.eq(header, self.encoder.alg())) {
                defer t.deinit();

                return Error.PasetoTokAlgoInvalid;
            }

            return t;
        }
    };
}

test {
    _ = @import("paseto_test.zig");
}
