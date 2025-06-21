//! By convention, main.zig is where your main function lives in the case that
//! you are building an executable. If you are making a library, the convention
//! is to delete this file and start with root.zig instead.

const std = @import("std");
const posix = std.posix;
const net = std.net;

pub const UdpAddr = struct {
    addr: posix.sockaddr,
    addrlen: posix.socklen_t,
};

pub const UdpServer = struct {
    sockfd: posix.fd_t,

    pub fn init(serverPort: u16) !UdpServer {
        const sockfd = try posix.socket(
            posix.AF.INET,
            posix.SOCK.DGRAM,
            0,
        );
        errdefer posix.close(sockfd);
        const addr = try net.Address.parseIp("127.0.0.1", serverPort);
        try posix.bind(sockfd, &addr.any, @sizeOf(posix.sockaddr.in));
        return UdpServer{ .sockfd = sockfd };
    }

    pub fn recv(self: *UdpServer, buf: []u8, addr: *UdpAddr) ![]u8 {
        var raw_addr: posix.sockaddr = undefined;
        var addrlen: posix.socklen_t = @sizeOf(posix.sockaddr);
        const n = try posix.recvfrom(self.sockfd, buf, 0, &raw_addr, &addrlen);
        addr.* = UdpAddr{
            .addr = raw_addr,
            .addrlen = addrlen,
        };
        return buf[0..@as(usize, n)];
    }

    pub fn sendto(self: *UdpServer, data: []const u8, addr: UdpAddr) !void {
        const sent = try posix.sendto(self.sockfd, data, 0, &addr.addr, addr.addrlen);
        if (sent != data.len) return error.SendIncomplete;
    }

    pub fn deinit(self: *UdpServer) void {
        posix.close(self.sockfd);
    }
};

pub const UdpClient = struct {
    sockfd: posix.fd_t,
    server_ip: []const u8,
    server_port: u16,

    pub fn init(server_ip: []const u8, server_port: u16) !UdpClient {
        const sockfd = try posix.socket(
            posix.AF.INET,
            posix.SOCK.DGRAM,
            0,
        );
        errdefer posix.close(sockfd);
        return UdpClient{
            .sockfd = sockfd,
            .server_ip = server_ip,
            .server_port = server_port,
        };
    }

    pub fn send(self: *UdpClient, data: []const u8) !void {
        const addr = try net.Address.parseIp(self.server_ip, self.server_port);
        const sent = try posix.sendto(self.sockfd, data, 0, &addr.any, @sizeOf(posix.sockaddr));
        if (sent != data.len) return error.SendIncomplete;
    }

    pub fn recv(self: *UdpClient, buf: []u8) ![]u8 {
        const n = try posix.recv(self.sockfd, buf, 0);
        return buf[0..@as(usize, n)];
    }

    pub fn deinit(self: *UdpClient) void {
        posix.close(self.sockfd);
    }
};

const defaultPort = 21612;
fn serveEcho() !void {
    var server = try UdpServer.init(defaultPort);
    defer server.deinit();
    var buf: [2048]u8 = undefined;
    while (true) {
        var src_addr: UdpAddr = undefined;
        const msg = try server.recv(&buf, &src_addr);
        std.debug.print("Echoing {d} bytes\n", .{msg.len});
        try server.sendto(msg, src_addr);
    }
}
fn clientSend() !void {
    var udp_client = try UdpClient.init("127.0.0.1", defaultPort);
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

test "UDP echo" {
    var buf: [2048]u8 = undefined;
    var server = try UdpServer.init(defaultPort);
    defer server.deinit();

    var client = try UdpClient.init("127.0.0.1", defaultPort);
    defer client.deinit();

    const msg = "test udp";
    try client.send(msg);

    var src_addr: UdpAddr = undefined;
    const received = try server.recv(&buf, &src_addr);
    try std.testing.expectEqualStrings(msg, received);

    try server.sendto(received, src_addr);

    const echoed = try client.recv(&buf);
    try std.testing.expectEqualStrings(msg, echoed);
}
