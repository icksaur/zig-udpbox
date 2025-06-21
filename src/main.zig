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

    pub fn recv(self: *UdpServer, buf: []u8, addr: *UdpAddr) !usize {
        var raw_addr: posix.sockaddr = undefined;
        var addrlen: posix.socklen_t = @sizeOf(posix.sockaddr);
        const n = try posix.recvfrom(self.sockfd, buf, 0, &raw_addr, &addrlen);
        addr.* = UdpAddr{
            .addr = raw_addr,
            .addrlen = addrlen,
        };
        return n;
    }

    pub fn sendto(self: *UdpServer, data: []const u8, addr: UdpAddr) !usize {
        return try posix.sendto(self.sockfd, data, 0, &addr.addr, addr.addrlen);
    }

    pub fn deinit(self: *UdpServer) void {
        posix.close(self.sockfd);
    }
};

pub const UdpClient = struct {
    sockfd: posix.fd_t,
    server_addr: posix.sockaddr,
    server_addrlen: posix.socklen_t,

    pub fn init(serverAddress: UdpAddr) !UdpClient {
        const sockfd = try posix.socket(
            posix.AF.INET,
            posix.SOCK.DGRAM,
            0,
        );
        errdefer posix.close(sockfd);
        // Do not bind; let the OS choose the port automatically
        return UdpClient{
            .sockfd = sockfd,
            .server_addr = serverAddress.addr,
            .server_addrlen = serverAddress.addrlen,
        };
    }

    pub fn send(self: *UdpClient, data: []const u8) !usize {
        return try posix.sendto(self.sockfd, data, 0, &self.server_addr, self.server_addrlen);
    }

    pub fn recv(self: *UdpClient, buf: []u8) !usize {
        // Optionally, you can get the sender address, but here we ignore it
        return try posix.recv(self.sockfd, buf, 0);
    }

    pub fn deinit(self: *UdpClient) void {
        posix.close(self.sockfd);
    }
};

const defaultPort = 21612;
fn serve() !void {
    var server = try UdpServer.init(defaultPort);
    defer server.deinit();
    var buf: [2048]u8 = undefined;
    while (true) {
        var src_addr: UdpAddr = undefined;
        const n = try server.recv(&buf, &src_addr);
        std.debug.print("Echoing {d} bytes\n", .{n});
        const msg = buf[0..@as(usize, n)];
        _ = try server.sendto(msg, src_addr);
    }
}
fn client() !void {
    const addr = try net.Address.parseIp("127.0.0.1", defaultPort);
    const server_addr = UdpAddr{
        .addr = addr.any,
        .addrlen = @sizeOf(posix.sockaddr),
    };
    var udp_client = try UdpClient.init(server_addr);
    defer udp_client.deinit();

    const msg = "udp test";
    _ = try udp_client.send(msg);

    var buf: [2048]u8 = undefined;
    const n = try udp_client.recv(&buf);
    try std.io.getStdOut().writer().writeAll(buf[0..@as(usize, n)]);
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
        try serve();
    } else if (std.mem.eql(u8, mode, "client")) {
        try client();
    } else {
        std.debug.print("Unknown mode: {s}\nUsage: zigudp <server|client>\n", .{mode});
    }
}

test "UDP echo" {
    var buf: [2048]u8 = undefined;
    // Start server: receive one message and echo it back
    var server = try UdpServer.init(defaultPort);
    defer server.deinit();

    // Prepare client
    const addr = try net.Address.parseIp("127.0.0.1", defaultPort);
    const server_addr = UdpAddr{
        .addr = addr.any,
        .addrlen = @sizeOf(posix.sockaddr),
    };
    var udp_client = try UdpClient.init(server_addr);
    defer udp_client.deinit();

    // Client sends message
    const msg = "test udp";
    _ = try udp_client.send(msg);

    // Server receives message
    var src_addr: UdpAddr = undefined;
    const n = try server.recv(&buf, &src_addr);
    try std.testing.expectEqualStrings(msg, buf[0..@as(usize, n)]);

    // Server echos back
    const echo_msg = buf[0..@as(usize, n)];
    _ = try server.sendto(echo_msg, src_addr);

    // Client receives echo
    const m = try udp_client.recv(&buf);
    try std.testing.expectEqualStrings(msg, buf[0..@as(usize, m)]);
}
