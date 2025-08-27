const std = @import("std");
const fmt = std.fmt;
const fs = std.fs;
const heap = std.heap;
const mem = std.mem;
const Compile = std.Build.Step.Compile;

fn initLibConfig(b: *std.Build, lib: *Compile) void {
    lib.linkLibC();
    lib.addIncludePath(b.path("src/"));
    lib.addIncludePath(b.path("src/noise_xk/include"));
    lib.addIncludePath(b.path("src/noise_xk/include/karmel"));
    lib.addIncludePath(b.path("src/noise_xk/include/karmel/minimal"));
    //lib.want_lto = false;
}

pub fn build(b: *std.Build) !void {
    const root_path = b.pathFromRoot(".");
    var cwd = try fs.openDirAbsolute(root_path, .{});
    defer cwd.close();

    const src_path = "src/";
    const src_dir = try fs.Dir.openDir(cwd, src_path, .{ .iterate = true, .no_follow = true });

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const static_lib = b.addLibrary(.{
        .name = "liboprf",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
    });

    const libsodium_package = b.dependency("libsodium", .{
        .target = target,
        .optimize = optimize,
        .@"test" = false, // `test` is a keyword in zig
        .static = true,
        .shared = false
    });
    static_lib.linkLibrary(libsodium_package.artifact("sodium"));
    static_lib.addIncludePath(libsodium_package.path("include"));

    b.installArtifact(static_lib);
    initLibConfig(b, static_lib);

    const flags = &.{
        "-fvisibility=hidden",
        "-fPIC",
        "-fwrapv",
    };

    static_lib.installHeadersDirectory(b.path(src_path ++ "/noise_xk/include"), "oprf/noise_xk", .{});

    const allocator = heap.page_allocator;

    var walker = try src_dir.walk(allocator);
    while (try walker.next()) |entry| {
        if(mem.startsWith(u8, entry.path, "tests")) continue;

        const name = entry.basename;
        if (mem.endsWith(u8, name, ".c")) {
            const full_path = try fmt.allocPrint(allocator, "{s}/{s}", .{ src_path, entry.path });
            static_lib.addCSourceFile(.{
                .file = b.path(full_path),
                .flags = flags,
            });
        } else if (mem.endsWith(u8, name, ".h")) {
            const full_path = try fmt.allocPrint(allocator, "{s}/{s}", .{ src_path, entry.path });
            if(!mem.startsWith(u8, entry.path, "noise_xk")) {
                const full_dest = try fmt.allocPrint(allocator, "oprf/{s}", .{ name });
                static_lib.installHeader(b.path(full_path), full_dest);
            }
        }
    }
}
