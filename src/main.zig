//! By convention, main.zig is where your main function lives in the case that
//! you are building an executable. If you are making a library, the convention
//! is to delete this file and start with root.zig instead.

const std = @import("std");
const udp = @import("udp.zig");

const defaultPort = 21612;
fn serveEcho() !void {
    var server = try udp.UdpServer.init(defaultPort);
    defer server.deinit();
    var buf: [2048]u8 = undefined;
    while (true) {
        var src_addr: udp.UdpAddr = undefined;
        const msg = try server.recv(&buf, &src_addr);
        std.debug.print("Echoing {d} bytes\n", .{msg.len});
        try server.sendto(msg, src_addr);
    }
}
fn clientSend() !void {
    var udp_client = try udp.UdpClient.init("127.0.0.1", defaultPort);
    defer udp_client.deinit();

    const msg = "udp test";
    try udp_client.send(msg);

    var buf: [2048]u8 = undefined;
    const received = try udp_client.recv(&buf);
    try std.io.getStdOut().writer().writeAll(received);
    try std.io.getStdOut().writer().writeAll("\n");
}

pub fn main() !void {
    var args = std.process.args();
    _ = args.next(); // skip program name
    const mode = args.next() orelse {
        std.debug.print("Usage: zigudp <server|client>\n", .{});
        return;
    };
    if (std.mem.eql(u8, mode, "server")) {
        try serveEcho();
    } else if (std.mem.eql(u8, mode, "client")) {
        try clientSend();
    } else {
        std.debug.print("Unknown mode: {s}\nUsage: zigudp <server|client>\n", .{mode});
    }
}
