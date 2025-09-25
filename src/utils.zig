const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const Allocator = std.mem.Allocator;

pub const json = std.json;
pub const base64 = std.base64;

pub const JsonParsedValue = json.Parsed(json.Value);

pub fn base64Decode(alloc: Allocator, input: []const u8) ![]const u8 {
    const decoder = base64.standard.Decoder;
    const decode_len = try decoder.calcSizeForSlice(input);

    const buffer = try alloc.alloc(u8, decode_len);
    _ = decoder.decode(buffer, input) catch {
        defer alloc.free(buffer);

        return "";
    };

    return buffer[0..];
}

pub fn base64UrlEncode(alloc: Allocator, input: []const u8) ![]const u8 {
    const encoder = base64.url_safe_no_pad.Encoder;
    const encode_len = encoder.calcSize(input.len);

    const buffer = try alloc.alloc(u8, encode_len);
    const res = encoder.encode(buffer, input);

    return res;
}

pub fn base64UrlDecode(alloc: Allocator, input: []const u8) ![]const u8 {
    const decoder = base64.url_safe_no_pad.Decoder;
    const decode_len = try decoder.calcSizeForSlice(input);

    const buffer = try alloc.alloc(u8, decode_len);
    _ = decoder.decode(buffer, input) catch {
        defer alloc.free(buffer);

        return "";
    };

    return buffer[0..];
}

pub fn jsonEncode(alloc: Allocator, value: anytype) ![]const u8 {
    const out = try json.Stringify.valueAlloc(alloc, value, .{ .emit_null_optional_fields = false });

    return out;
}

pub fn jsonDecode(alloc: Allocator, value: []const u8) !json.Parsed(json.Value) {
    return json.parseFromSlice(json.Value, alloc, value, .{});
}

pub fn jsonDecodeT(comptime T: type, alloc: Allocator, value: []const u8) !json.Parsed(T) {
    return json.parseFromSlice(T, alloc, value, .{});
}

pub fn eq(rest: []const u8, needle: []const u8) bool {
    return std.mem.eql(u8, rest, needle);
}

// https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#authentication-padding
pub fn pre_auth_encoding(alloc: Allocator, pieces: []const []const u8) ![]u8 {
    // Precompute length to allocate the buffer
    // PieceCount (8B) || ( PieceLen (8B) || Piece (*B) )*
    var buf_len: usize = 8;
    for (pieces) |piece| {
        buf_len += 8 + piece.len;
    }

    // Pre-allocate the buffer
    var output = try alloc.alloc(u8, buf_len);
    errdefer alloc.free(output);

    // Encode piece count
    mem.writeInt(u64, output[0..8], @as(u64, @intCast(pieces.len)), .little);

    var offset: usize = 8;
    // For each element
    for (pieces) |piece| {
        // Encode size
        mem.writeInt(u64, output[offset..][0..8], @as(u64, @intCast(piece.len)), .little);
        offset += 8;

        // Encode data
        @memcpy(output[offset..][0..piece.len], piece);
        offset += piece.len;
    }

    return output;
}

pub fn TestRNG(comptime buf: []const u8) type {
    return struct {
        pub fn fill(_: *anyopaque, buffer: []u8) void {
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

test "base64UrlEncode" {
    const alloc = testing.allocator;

    const msg = "test-data";
    const check = "dGVzdC1kYXRh";

    const res = try base64UrlEncode(alloc, msg);
    defer alloc.free(res);
    try testing.expectEqualStrings(check, res);

    const res2 = try base64UrlDecode(alloc, check);
    defer alloc.free(res2);
    try testing.expectEqualStrings(msg, res2);

    const res3 = try base64Decode(alloc, check);
    defer alloc.free(res3);
    try testing.expectEqualStrings(msg, res3);
}

test "jsonEncode" {
    const alloc = testing.allocator;

    const msg = .{
        .typ = "test-data",
    };
    const check = "{\"typ\":\"test-data\"}";

    const res = try jsonEncode(alloc, msg);
    defer alloc.free(res);
    try testing.expectEqualStrings(check, res);

    const res2 = try jsonDecode(alloc, check);
    defer res2.deinit();
    try testing.expectEqualStrings(msg.typ, res2.value.object.get("typ").?.string);

    const msg3 = struct {
        typ: []const u8,
    };

    const res3 = try jsonDecodeT(msg3, alloc, check);
    defer res3.deinit();
    try testing.expectEqualStrings(msg.typ, res3.value.typ);
}

test "pre_auth_encoding" {
    {
        const str = try pre_auth_encoding(testing.allocator, &[_][]const u8{});
        defer testing.allocator.free(str);
        try testing.expectFmt("0000000000000000", "{x}", .{str});
    }
    {
        const str = try pre_auth_encoding(testing.allocator, &[_][]const u8{"test"});
        defer testing.allocator.free(str);
        //try testing.expectEqual(&[_]u8{
        //    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Count
        //    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Length
        //    't',  'e',  's',  't',
        //}, str);
        try testing.expectFmt("0100000000000000040000000000000074657374", "{x}", .{str});
    }
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
