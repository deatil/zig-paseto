const std = @import("std");
const json = std.json;
const Allocator = std.mem.Allocator;

pub const Ed25519 = std.crypto.sign.Ed25519;
pub const ecdsa = std.crypto.sign.ecdsa;
pub const EcdsaP384Sha384 = ecdsa.EcdsaP384Sha384;

pub const rsa = @import("rsa/rsa.zig");
pub const parser = @import("parser.zig");
pub const utils = @import("utils.zig");
pub const Token = @import("token.zig").Token;

pub const v1 = @import("v1.zig");
pub const v1_local = @import("v1_local.zig");
pub const v1_public = @import("v1_public.zig");

pub const v2 = @import("v2.zig");
pub const v2_local = @import("v2_local.zig");
pub const v2_public = @import("v2_public.zig");

pub const v3 = @import("v3.zig");
pub const v3_local = @import("v3_local.zig");
pub const v3_public = @import("v3_public.zig");

pub const v4 = @import("v4.zig");
pub const v4_local = @import("v4_local.zig");
pub const v4_public = @import("v4_public.zig");

pub const V1Local = Paseto(v1_local.V1Local, []const u8, []const u8);
pub const V1Public = Paseto(v1_public.V1Public, rsa.SecretKey, rsa.PublicKey);

pub const V2Local = Paseto(v2_local.V2Local, []const u8, []const u8);
pub const V2Public = Paseto(v2_public.V2Public, Ed25519.SecretKey, Ed25519.PublicKey);

pub const V3Local = Paseto(v3_local.V3Local, []const u8, []const u8);
pub const V3Public = Paseto(v3_public.V3Public, EcdsaP384Sha384.SecretKey, EcdsaP384Sha384.PublicKey);

pub const V4Local = Paseto(v4_local.V4Local, []const u8, []const u8);
pub const V4Public = Paseto(v4_public.V4Public, Ed25519.SecretKey, Ed25519.PublicKey);

pub const Error = error{
    PasetoTokenInvalid,
    PasetoTokAlgoInvalid,
};

pub fn Paseto(comptime Encoder: type, comptime EncodeKeyType: type, comptime DecodeKeyType: type) type {
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

        // encode paseto token
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

        // decode paseto token
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
