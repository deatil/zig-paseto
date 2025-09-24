const std = @import("std");
const testing = std.testing;
const blake2 = std.crypto.hash.blake2;

const utils = @import("utils.zig");

// KeyLength is the requested encryption key size.
pub const key_length = 32;

pub const nonce_length = 24;
pub const mac_length = 24;

pub fn mac(ak: []const u8, payload: []const u8) [mac_length]u8 {
    const Blake2bMac = blake2.Blake2b(mac_length * 8);

    var mac_hash = Blake2bMac.init(.{
        .key = ak,
    });

    var out: [Blake2bMac.digest_length]u8 = undefined;

    mac_hash.update(payload);
    mac_hash.final(out[0..]);

    return out;
}

test "mac" {
    const ak = "test-ak";
    const payload = "test-payload";
    const res = mac(ak, payload);
    try testing.expectFmt("59929490cd1bb92683d7ae254b255388c491ef4f7a64c452", "{x}", .{res});
}
