## Zig-paseto 

A Paseto library for zig.


### Env

 - Zig >= 0.16.0-dev.164+bc7955306.


### Adding zig-paseto as a dependency

Add the dependency to your project:

```sh
zig fetch --save=zig-paseto git+https://github.com/deatil/zig-paseto#main
```

or use local path to add dependency at `build.zig.zon` file

```zig
.{
    .dependencies = .{
        .@"zig-paseto" = .{
            .path = "./lib/zig-paseto",
        },
        ...
    }
}
```

And the following to your `build.zig` file:

```zig
const zig_paseto_dep = b.dependency("zig-paseto", .{});
exe.root_module.addImport("zig-paseto", zig_paseto_dep.module("zig-paseto"));
```

The `zig-paseto` structure can be imported in your application with:

```zig
const paseto = @import("zig-paseto");
```


### Get Starting

~~~zig
const std = @import("std");
const paseto = @import("zig-paseto");

pub fn main() !void {
    const alloc = std.heap.page_allocator;

    const key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f";

    var buf: [32]u8 = undefined;
    const k = try std.fmt.hexToBytes(&buf, key);

    const m = "{\"data\":\"this is a signed message\",\"exp\":\"2022-01-01T00:00:00+00:00\"}";
    const f = "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
    const i = "{\"test-vector\":\"4-S-3\"}";

    var e = paseto.V4Local.init(alloc);
    defer e.deinit();

    try e.withMessage(m);
    try e.withFooter(f);
    try e.withImplicit(i);

    const token = try e.encode(crypto.random, k);
    defer alloc.free(token);
    
    // output: 
    // make paseto jwt: v4.local.G-ToOUO6A-LGTVrBKiVn7najk-XOBR2a4olurkkWrLgM9sKOf6tNlMpKbSZpI70E5MzgdnWq6yplehnR2VeLR4VTmGMZYDI0VMotPJpKJeBuS7xDoCsm8z_5wA9af2ZtTfrlMY5ErELyiqx5pqdVAzSBP9ZM6-Qxo4oHTnWAqjENeOHdYA.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9
    std.debug.print("make paseto jwt: {s} \n", .{token_string});

    // ====================

    // parse token
    var p = paseto.V4Local.init(alloc);
    defer p.deinit();

    try p.withImplicit(i);

    try p.decode(token, k);
    
    // output: 
    // message: this is a signed message
    const message = try p.getMessage();
    defer message.deinit();
    std.debug.print("message: {s} \n", .{g_m.value.object.get("data").?.string});
}
~~~


### Encode Methods

The Paseto library have Encode methods:

 - `v4.local`: paseto.V4Local
 - `v4.public`: paseto.V4Public


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
