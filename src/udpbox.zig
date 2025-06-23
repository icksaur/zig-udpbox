const std = @import("std");
const crypto = std.crypto;
const X25519 = crypto.dh.X25519;
const Box = crypto.nacl.Box;
const SecretBox = crypto.nacl.SecretBox;
const AuthError = crypto.errors.AuthenticationError;
const udp = @import("udp.zig");

const generic_message: u8 = 0x00;
const connect_bit: u8 = 0x01;
const ciphertext_buffer_size = 2048;

fn incrementNonce(nonce: []u8) void {
    for (nonce) |*byte| {
        if (byte.* < 0xff) {
            byte.* += 1;
            return;
        }
        byte.* = 0;
    }
}

pub const UdpBoxError = error{
    DuplicateClientId,
    InvalidMessage,
    InvalidClient,
    SendIncomplete,
    AuthenticationFailed,
};

const encrypted_size = X25519.public_length + Box.tag_length;
const handshake_size = encrypted_size + Box.nonce_length + 2;

const UdpClient = struct {
    client_keypair: X25519.KeyPair,
    ephemeral_keypair: X25519.KeyPair,
    server_public_key: [X25519.public_length]u8,
    client: udp.UdpClient,
    client_id: u8,
    nonce: [Box.nonce_length]u8 = undefined,
    ciphertext_buffer: [Box.tag_length + 2048]u8 = undefined,
    shared_secret: [X25519.shared_length]u8 = undefined,

    pub fn init(client_keypair: X25519.KeyPair, server_public_key: *const [X25519.public_length]u8, clientId: u8, serverIp: []const u8, serverPort: u16) !UdpClient {
        var client = UdpClient{
            .client_keypair = client_keypair,
            .client = try udp.UdpClient.init(serverIp, serverPort),
            .client_id = clientId,
            .ephemeral_keypair = X25519.KeyPair.generate(),
            .server_public_key = server_public_key.*,
        };
        client.server_public_key = server_public_key.*;
        crypto.random.bytes(&client.nonce);
        client.shared_secret = try X25519.scalarmult(client.ephemeral_keypair.secret_key, client.server_public_key);
        return client;
    }
    pub fn deinit(self: *UdpClient) void {
        self.client.deinit();
    }
    // Sends an epheremal public key to the server.  The server uses this to establish a shared secret with the client.
    // The server will use the client's public key to decrypt the handshake
    pub fn sendHandshake(self: *UdpClient) !void {
        var payload = self.ciphertext_buffer[0..handshake_size];
        const ciphertext = self.ciphertext_buffer[0..encrypted_size];
        const handshake_nonce = self.ciphertext_buffer[encrypted_size .. encrypted_size + Box.nonce_length];
        crypto.random.bytes(handshake_nonce);
        try Box.seal(
            ciphertext,
            &self.ephemeral_keypair.public_key,
            handshake_nonce.*,
            self.server_public_key,
            self.client_keypair.secret_key,
        );
        payload[payload.len - 2] = self.client_id;
        payload[payload.len - 1] = connect_bit;
        try self.client.send(payload);
    }
    // Sends an encrypted message to the server using the shared secret established during the handshake
    pub fn send(self: *UdpClient, message: []const u8) !void {
        const payload = self.ciphertext_buffer[0 .. message.len + SecretBox.tag_length + self.nonce.len + 2];
        const ciphertext = payload[0 .. message.len + SecretBox.tag_length];
        SecretBox.seal(
            ciphertext,
            message,
            self.nonce,
            self.shared_secret,
        );
        const ciphertext_size = message.len + SecretBox.tag_length;
        @memcpy(payload[ciphertext_size .. ciphertext_size + self.nonce.len], &self.nonce);
        payload[payload.len - 2] = self.client_id;
        payload[payload.len - 1] = generic_message;
        try self.client.send(self.ciphertext_buffer[0 .. ciphertext_size + self.nonce.len + 2]);
        incrementNonce(&self.nonce);
    }
    pub fn recv(self: *UdpClient, buf: []u8) ![]u8 {
        const payload = try self.client.recv(buf);
        if (payload.len < SecretBox.tag_length + SecretBox.nonce_length) {
            return error.InvalidMessage;
        }
        const ciphertext = payload[0 .. payload.len - SecretBox.nonce_length];
        var nonce: [SecretBox.nonce_length]u8 = undefined;
        const message = buf[0 .. ciphertext.len - SecretBox.tag_length];
        @memcpy(&nonce, payload[ciphertext.len .. ciphertext.len + SecretBox.nonce_length]);
        try SecretBox.open(message, ciphertext, nonce, self.shared_secret);
        return message;
    }
};

const UdpServer = struct {
    server_keypair: X25519.KeyPair,
    server: udp.UdpServer,
    nonce: [Box.nonce_length]u8 = undefined,
    ciphertext_buffer: [Box.tag_length + ciphertext_buffer_size]u8 = undefined,
    client_keys: std.AutoHashMap(u8, [X25519.public_length]u8),
    client_addresses: std.AutoHashMap(u8, udp.UdpAddr),
    client_shared_secrets: std.AutoHashMap(u8, [X25519.shared_length]u8),

    // todo: rationalize allocator
    pub fn init(server_keypair: X25519.KeyPair, serverPort: u16) !UdpServer {
        var server = UdpServer{
            .server_keypair = server_keypair,
            .server = try udp.UdpServer.init(serverPort),
            .client_keys = std.AutoHashMap(u8, [X25519.public_length]u8).init(std.heap.page_allocator),
            .client_addresses = std.AutoHashMap(u8, udp.UdpAddr).init(std.heap.page_allocator),
            .client_shared_secrets = std.AutoHashMap(u8, [X25519.shared_length]u8).init(std.heap.page_allocator),
        };
        crypto.random.bytes(&server.nonce);
        return server;
    }
    pub fn deinit(self: *UdpServer) void {
        self.client_keys.deinit();
        self.client_shared_secrets.deinit();
        self.client_addresses.deinit();
        self.server.deinit();
    }
    pub fn addClient(self: *UdpServer, client_public_key: [X25519.public_length]u8, client_id: u8) !void {
        if (self.client_keys.contains(client_id)) {
            return error.DuplicateClientId; // client_id already exists
        }
        try self.client_keys.put(client_id, client_public_key);
    }
    fn getClientKey(self: *UdpServer, client_id: u8) ![X25519.public_length]u8 {
        return self.client_keys.get(client_id) orelse return error.InvalidClient;
    }
    pub fn recv(self: *UdpServer, buf: []u8, client_id_out: *u8) ![]u8 {
        while (true) {
            var address: udp.UdpAddr = undefined;
            const payload = try self.server.recv(buf, &address);
            const client_id = payload[payload.len - 2];
            const message_type = payload[payload.len - 1];
            if (false == self.client_keys.contains(client_id)) {
                return error.InvalidClient; // client_id not recognized
            }
            if (message_type == connect_bit) {
                if (payload.len < handshake_size) {
                    std.debug.print("payload.len {} is less than handshake_size {}", .{ payload.len, handshake_size });
                    return error.InvalidMessage;
                }
                const ciphertext = payload[0..encrypted_size];
                var nonce: [Box.nonce_length]u8 = undefined;
                @memcpy(&nonce, payload[encrypted_size .. encrypted_size + Box.nonce_length]);
                const message = buf[0 .. encrypted_size - Box.tag_length];
                try Box.open(
                    message,
                    ciphertext,
                    nonce,
                    try self.getClientKey(client_id),
                    self.server_keypair.secret_key,
                );
                var ephemeral_public_key: [X25519.public_length]u8 = undefined;
                @memcpy(&ephemeral_public_key, message[0..X25519.public_length]);
                const client_shared_secret = try X25519.scalarmult(self.server_keypair.secret_key, ephemeral_public_key);
                try self.client_shared_secrets.put(client_id, client_shared_secret); // handle OOM better?
                try self.client_addresses.put(client_id, address);
            } else if (message_type == generic_message) {
                const ciphertext = payload[0 .. payload.len - SecretBox.nonce_length - 2];
                var nonce: [SecretBox.nonce_length]u8 = undefined;
                @memcpy(&nonce, payload[ciphertext.len .. ciphertext.len + SecretBox.nonce_length]);
                const shared_secret = self.client_shared_secrets.get(client_id) orelse return error.InvalidClient;
                const message = buf[0 .. ciphertext.len - SecretBox.tag_length];
                try SecretBox.open(message, ciphertext, nonce, shared_secret);
                client_id_out.* = client_id;
                return message;
            } else {
                return error.InvalidMessage;
            }
        }
    }
    pub fn send(self: *UdpServer, client_id: u8, message: []const u8) !void {
        const shared_secret = self.client_shared_secrets.get(client_id) orelse return error.InvalidClient;
        const client_address = self.client_addresses.get(client_id) orelse return error.InvalidClient;
        if (message.len + SecretBox.tag_length + SecretBox.nonce_length > self.ciphertext_buffer.len) {
            return error.InvalidMessage; // message too long
        }
        const ciphertext_size = message.len + SecretBox.tag_length;
        var nonce: [Box.nonce_length]u8 = undefined;
        crypto.random.bytes(&nonce);
        SecretBox.seal(
            self.ciphertext_buffer[0..ciphertext_size],
            message,
            nonce,
            shared_secret,
        );
        @memcpy(self.ciphertext_buffer[ciphertext_size .. ciphertext_size + Box.nonce_length], &nonce);
        try self.server.sendto(self.ciphertext_buffer[0 .. ciphertext_size + Box.nonce_length], client_address);
    }
};

test "UDPBox client-server" {
    const alice = X25519.KeyPair.generate();
    const bob = X25519.KeyPair.generate();
    const alice_id: u8 = 1;
    const port: u16 = 21612;

    var alice_client = try UdpClient.init(alice, &bob.public_key, alice_id, "127.0.0.1", port);
    defer alice_client.deinit();

    var bob_server = try UdpServer.init(bob, port);
    defer bob_server.deinit();

    try bob_server.addClient(alice.public_key, alice_id);

    try alice_client.sendHandshake();
    try alice_client.send("Hello, Bob!");

    var buf: [handshake_size]u8 = undefined;
    var client_id: u8 = 0;
    var received = try bob_server.recv(&buf, &client_id);
    try std.testing.expectEqualStrings("Hello, Bob!", received);
    try std.testing.expectEqual(alice_id, client_id);

    try bob_server.send(client_id, "Hello, Alice!");
    received = try alice_client.recv(&buf);
    try std.testing.expectEqualStrings("Hello, Alice!", received);
}

test "X25519 shared secret" {
    const alice = X25519.KeyPair.generate();
    const bob = X25519.KeyPair.generate();
    try std.testing.expect(std.mem.eql(u8, &alice.public_key, &bob.public_key) == false);

    const alice_pub = alice.public_key;
    const bob_pub = bob.public_key;

    const alice_shared = try X25519.scalarmult(alice.secret_key, bob_pub);
    const bob_shared = try X25519.scalarmult(bob.secret_key, alice_pub);

    try std.testing.expectEqualSlices(u8, &alice_shared, &bob_shared);

    const message = "Hello, World!";
    var ciphertext: [message.len + SecretBox.tag_length]u8 = undefined;
    var nonce: [SecretBox.nonce_length]u8 = undefined;
    crypto.random.bytes(&nonce);
    SecretBox.seal(&ciphertext, message, nonce, alice_shared);

    var decrypted: [message.len]u8 = undefined;
    try SecretBox.open(&decrypted, &ciphertext, nonce, alice_shared);

    try std.testing.expectEqualStrings(message, &decrypted);
}

test "NaCl Box encryption" {
    const alice = X25519.KeyPair.generate();
    const bob = X25519.KeyPair.generate();

    const message = "Hello, Bob!";
    var encrypted: [message.len + Box.tag_length]u8 = undefined;
    var nonce: [Box.nonce_length]u8 = undefined;
    crypto.random.bytes(&nonce);

    try Box.seal(
        &encrypted,
        message,
        nonce,
        bob.public_key,
        alice.secret_key,
    );

    var decrypted: [message.len]u8 = undefined;
    try Box.open(
        &decrypted,
        &encrypted,
        nonce,
        alice.public_key,
        bob.secret_key,
    );

    try std.testing.expectEqualStrings(message, &decrypted);

    std.crypto.random.bytes(&nonce); // mess up the nonce

    try std.testing.expectError(AuthError.AuthenticationFailed, Box.open(
        &decrypted,
        &encrypted,
        nonce,
        alice.public_key,
        bob.secret_key,
    ));
}
