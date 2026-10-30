const std = @import("std");
const sockz5 = @import("sockz5");
const builtin = @import("builtin");

const net = @import("net.zig");
const utils = @import("utils.zig");
const io_utils = @import("io_utils.zig");
const constants = @import("constants.zig");

const BufferPool = @import("buffer_pool.zig").BufferPool;
const ChunkPool = @import("chunk_pool.zig").ChunkPool;

const IO = std.Io;
const posix = std.posix;
const linux = std.os.linux;

const OsError = utils.OsError;
const IO_Uring = linux.IoUring;
const IP_Address = IO.net.IpAddress;
const PosixAddress = IO.Threaded.PosixAddress;

const panic = std.debug.panic;
const assert = std.debug.assert;
const errno_as_error = utils.errno_as_error;
const address_to_posix = IO.Threaded.addressToPosix;

const AuthMethod = enum(u8) {
    none = 0,

    // https://en.wikipedia.org/wiki/Generic_Security_Services_Application_Programming_Interface
    gssapi = 1,

    // username and password
    credentials = 2,

    challenge_handshake_authentication_protocol = 3,

    challenge_response_authentication_method = 5,

    tls = 6,

    novell_directory_services_authentication = 7,

    // 3 .. 127 are assigned by IANA
    // 128 .. 254 are reserved for private methods
    unacceptable = 0xff,

    _, // Non exhaustive enum since the client could have some method we are not aware of.

    pub fn from_int(i: u8) ?AuthMethod {
        return std.enums.fromInt(AuthMethod, i) orelse null;
    }
};

const AuthNegotiationError = error{
    TooManyBytes, // Client specified a given count of methods but sent more data.
    NotEnoughBytes,
    InvalidSocksVersion,
    InvalidMethodsCount, // client sent `0 methods available` for example.
};

fn parse_auth_method_negotiation_request(buffer: []const u8) AuthNegotiationError![]const AuthMethod {
    assert(buffer.len > 0);
    if (buffer.len < auth_method_negotiation_request_message_min_size) return error.NotEnoughBytes;
    if (buffer.len > auth_method_negotiation_request_message_max_size) return error.TooManyBytes;

    if (buffer[0] != constants.socks_version) return error.InvalidSocksVersion;

    const methods_count: u8 = buffer[1];
    if (methods_count == 0) return error.InvalidMethodsCount;

    // NOTE: Should TooManyMethods be a distinct error ?
    const auth_methods: []const AuthMethod = std.mem.bytesAsSlice(AuthMethod, buffer[2..]);

    if (auth_methods.len > methods_count) return error.TooManyBytes;
    if (auth_methods.len < methods_count) return error.NotEnoughBytes;
    return auth_methods;
}

const CommandNegotiationError = error{
    TooManyBytes,
    NotEnoughBytes,

    InvalidSocksVersion,
    InvalidCommand,
    InvalidReservedByte,
    InvalidAddressType,

    InvalidDomainNameLength,
    InvalidDomainName,
    InvalidPort,
};

const CommandRequest = struct {
    command: Command,

    /// NOTE: The DST.PORT can be 0 for a few reasons:
    /// 1) UDP associate according to the RFC itself.
    /// 2) XMPP bytestreams. See: https://xmpp.org/extensions/xep-0065.html#direct-proto-establish
    /// TODO: document other use cases for port number 0.
    destination_address: union(enum(u1)) {
        posix_address: PosixAddress,
        domain_name: struct {
            fqdn: []const u8,
            port: u16,
        },
    },

    /// Requires that name resolution be performed before calling this function.
    pub fn address_family(command_request: *const CommandRequest) u32 {
        return switch (command_request.ip_address_type()) {
            .ipv4 => linux.AF.INET,
            .ipv6 => linux.AF.INET6,
        };
    }

    /// Requires that name resolution be performed before calling this function.
    pub fn ip_address_type(command_request: *const CommandRequest) enum(u1) { ipv4, ipv6 } {
        switch (command_request.destination_address) {
            .posix_address => |*posix_address| return switch (posix_address.any.family) {
                linux.AF.INET => .ipv4,
                linux.AF.INET6 => .ipv6,
                else => unreachable,
            },
            else => unreachable,
        }
    }

    /// Requires that name resolution be performed before calling this function.
    /// TODO: get rid of this.
    pub fn destination_ip_address(command_request: *const CommandRequest) u128 {
        switch (command_request.destination_address) {
            .posix_address => |*posix_address| {
                return switch (posix_address.any.family) {
                    linux.AF.INET => @as(u128, posix_address.in.addr),
                    linux.AF.INET6 => std.mem.readInt(u128, &posix_address.in6.addr, .big), // TODO: test the endianess.
                    else => unreachable,
                };
            },
            .domain_name => unreachable,
        }
    }

    pub fn destination_port(command_request: *const CommandRequest) u16 {
        return switch (command_request.destination_address) {
            .posix_address => |posix_address| switch (posix_address.any.family) {
                linux.AF.INET => posix_address.in.port,
                linux.AF.INET6 => posix_address.in6.port,
                else => unreachable,
            },
            .domain_name => |domain_info| domain_info.port,
        };
    }
};

/// TODO: implement.
/// https://en.wikipedia.org/wiki/Fully_qualified_domain_name#Definition
/// All valid domain names are valid as FQDNs.
fn is_valid_fully_qualified_domain_name(domain_name: []const u8) bool {
    _ = domain_name;
    return true;
}

fn parse_command_negotiation_request(buffer: []const u8) CommandNegotiationError!CommandRequest {
    assert(buffer.len > 0);
    if (buffer.len > command_negotiation_request_message_max_size) return error.TooManyBytes;
    if (buffer.len < command_negotiation_request_message_min_size) return error.NotEnoughBytes;

    // NOTE: Look into `command_negotiation_request_message_min_size` to know why i'm asserting with unreachable.
    var reader: IO.Reader = .fixed(buffer);
    const socks_version = reader.takeInt(u8, .native) catch unreachable;
    if (socks_version != constants.socks_version) return error.InvalidSocksVersion;

    const command_int = reader.takeInt(u8, .native) catch unreachable;
    const command = Command.from_int(command_int) orelse return error.InvalidCommand;

    const reserved_byte = reader.takeInt(u8, .native) catch unreachable;
    if (reserved_byte != 0) return error.InvalidReservedByte;

    const address_type_int = reader.takeInt(u8, .native) catch unreachable;
    const address_type = AddressType.from_int(address_type_int) orelse return error.InvalidAddressType;

    switch (address_type) {
        .domain_name => {
            const domain_name_length = reader.takeInt(u8, .native) catch unreachable;
            if (domain_name_length == 0) return error.InvalidDomainNameLength;

            const fqdn: []const u8 = reader.take(domain_name_length) catch return error.NotEnoughBytes;
            if (!is_valid_fully_qualified_domain_name(fqdn)) return error.InvalidDomainName;

            // NOTE: In reality port 0 is both a legitimate source and destination, however, it requires bypassing
            // the linux tcp/ip stack and reimplementing it yourself in userspace using raw(7).
            // Check here for more info: https://www.cyber-threat-intelligence.com/publications/IFIPNetworking-2019-port0.pdf
            const port = reader.takeInt(u16, .big) catch return error.NotEnoughBytes;
            if (command != .udp_associate and port == 0) return error.InvalidPort;

            if (reader.bufferedLen() != 0) return error.TooManyBytes;
            return CommandRequest{
                .command = command,
                .destination_address = .{
                    .domain_name = .{
                        .port = port,
                        .fqdn = fqdn,
                    },
                },
            };
        },
        .ipv4 => {
            const ip = reader.takeInt(u32, .big) catch return error.NotEnoughBytes;
            const port = reader.takeInt(u16, .big) catch return error.NotEnoughBytes;
            if (port == 0) return error.InvalidPort;

            if (reader.bufferedLen() != 0) return error.TooManyBytes;
            return CommandRequest{
                .command = command,
                .destination_address = .{
                    .posix_address = PosixAddress{ .in = linux.sockaddr.in{
                        .addr = std.mem.nativeToBig(u32, ip),
                        .port = std.mem.nativeToBig(u16, port),
                    } },
                },
            };
        },
        .ipv6 => {
            const ip: *[16]u8 = reader.takeArray(16) catch return error.NotEnoughBytes;
            const port = reader.takeInt(u16, .big) catch return error.NotEnoughBytes;
            if (port == 0) return error.InvalidPort;

            if (reader.bufferedLen() != 0) return error.TooManyBytes;
            return CommandRequest{
                .command = command,
                .destination_address = .{
                    .posix_address = PosixAddress{ .in6 = linux.sockaddr.in6{
                        .addr = ip.*,
                        .port = std.mem.nativeToBig(u16, port),
                        .flowinfo = 0,
                        .scope_id = 0,
                    } },
                },
            };
        },
    }
}

// VER(1) + METHOD(1).
const auth_method_negotiation_reply_message_size: u8 = 1 + 1;

const unacceptable_auth_method_reply_message: [auth_method_negotiation_reply_message_size]u8 = .{
    constants.socks_version,
    @intFromEnum(AuthMethod.unacceptable),
};

const accepted_tls_method_reply_message: [auth_method_negotiation_reply_message_size]u8 = .{
    constants.socks_version,
    @intFromEnum(AuthMethod.tls),
};

const accepted_none_method_reply_message: [auth_method_negotiation_reply_message_size]u8 = .{
    constants.socks_version,
    @intFromEnum(AuthMethod.none),
};

const accepted_credentials_method_reply_message: [auth_method_negotiation_reply_message_size]u8 = .{
    constants.socks_version,
    @intFromEnum(AuthMethod.credentials),
};

/// VER(1) + NMETHODS(1).
const auth_method_negotiation_request_message_min_size = 1 + 1;

/// NOTE: The real size is actually 1 + 1 + 255 = 257, but we don't tolerate clients sending that many methods, they are clearly malicious.
const auth_method_negotiation_request_message_max_size = std.math.maxInt(u8);

/// The largest command negotiation message is one which contains a domain_name of length 255
/// VER(1) + CMD(1) + RSV(1) + ATYP(1) + DST.ADDR(1 + 255) + DST.PORT(2).
const command_negotiation_request_message_max_size = 1 + 1 + 1 + 1 + (1 + 255) + 2; // 262

/// The smallest command negotiation message that can be parsed but contains invalid data (0 length domain name).
/// VER(1) + CMD(1) + RSV(1) + ATYP(1) + DST.ADDR(1) + DST.PORT(2).
const command_negotiation_request_message_min_size = 1 + 1 + 1 + 1 + (1 + 0) + 2;

const command_negotiation_request_message_ipv4_size = 1 + 1 + 1 + 1 + 4 + 2;
const command_negotiation_request_message_ipv6_size = 1 + 1 + 1 + 1 + 16 + 2;

/// VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(4) + BND.PORT(2).
const command_negotiation_failure_reply_message_size = 1 + 1 + 1 + 1 + 4 + 2;

/// VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(4) + BND.PORT(2).
const command_negotiation_success_ipv4_reply_message_size = 1 + 1 + 1 + 1 + 4 + 2;

/// VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(16) + BND.PORT(2).
const command_negotiation_success_ipv6_reply_message_size = 1 + 1 + 1 + 1 + 16 + 2;

/// Same as the command_negotiation_request in size.
/// VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(1+255) + BND.PORT(2).
const command_negotiation_success_reply_message_max_size = 1 + 1 + 1 + 1 + (1 + 255) + 2;

/// TODO: Reject any length (ULEN/PLEN) equal to zero..
/// VER(1) + ULEN(1) + UNAME(1) + PLEN(1) + PASSWD(1)
const credentials_sub_negotiation_request_message_min_size = 1 + 1 + 1 + 1 + 1;

/// VER(1) + ULEN(1) + UNAME(255) + PLEN(1) + PASSWD(255) = 513.
const credentials_sub_negotiation_request_message_max_size = 1 + 1 + 255 + 1 + 255;

/// VER(1) + STATUS(1)
const credentials_sub_negotiation_reply_message_size = 1 + 1;

const sub_negotiation_version = 1;

const sub_negotiation_success: u8 = 0;
const sub_negotiation_failure: u8 = 1;

const credentials_sub_negotiation_success_reply_message = [credentials_sub_negotiation_reply_message_size]u8{
    constants.socks_version,
    sub_negotiation_success,
};

const credentials_sub_negotiation_failure_reply_message = [credentials_sub_negotiation_reply_message_size]u8{
    constants.socks_version,
    sub_negotiation_failure,
};

const CredentialsRequest = struct {
    username: []const u8,
    password: []const u8,
};

const CredentialsError = error{
    InvalidUsername,
    InvalidPassword,

    InvalidUsernameLen,
    InvalidPasswordLen,

    InvalidSocksVersion,
    NotEnoughBytes,
    TooManyBytes,
};

pub fn validate_username(username: []const u8) CredentialsError!void {
    // TODO: add more validation logic, like minimum required characters of certain types etc.
    assert(username.len <= std.math.maxInt(u8));
    if (username.len < constants.min_username_length) return error.InvalidUsernameLen;
}

pub fn validate_password(password: []const u8) CredentialsError!void {
    // TODO: add more validation logic, like minimum required characters of certain types etc.
    assert(password.len <= std.math.maxInt(u8));
    if (password.len < constants.min_password_length) return error.InvalidPasswordLen;
}

fn parse_and_validate_credentials_sub_negotiation_request(buffer: []const u8) CredentialsError!CredentialsRequest {
    assert(buffer.len > 0);
    if (buffer.len < credentials_sub_negotiation_request_message_min_size) return error.NotEnoughBytes;
    if (buffer.len > credentials_sub_negotiation_request_message_max_size) return error.TooManyBytes;

    var reader: IO.Reader = .fixed(buffer);
    const socks_version = reader.takeInt(u8, .native) catch return error.NotEnoughBytes;
    if (socks_version != constants.socks_version) return error.InvalidSocksVersion;

    const username_len = reader.takeInt(u8, .native) catch return error.NotEnoughBytes;
    const username: []const u8 = reader.take(username_len) catch return error.NotEnoughBytes;
    try validate_username(username);

    const password_len = reader.takeInt(u8, .native) catch return error.NotEnoughBytes;
    const password: []const u8 = reader.take(password_len) catch return error.NotEnoughBytes;
    try validate_password(password);

    if (reader.bufferedLen() != 0) return error.TooManyBytes;
    return CredentialsRequest{
        .username = username,
        .password = password,
    };
}

const available_auth_methods = [_]AuthMethod{.none};

const Command = enum(u8) {
    none = 0,
    connect = 1,
    bind = 2,
    udp_associate = 3,

    pub fn from_int(i: u8) ?Command {
        if (i == 0) {
            return null;
        }
        return std.enums.fromInt(Command, i) orelse null;
    }
};

const Reply = enum(u8) {
    success = 0,
    socks_server_failure = 1,
    ruleset_violation = 2,
    network_unreachable = 3,
    host_unreachable = 4,
    connection_refused = 5,
    ttl_expired = 6,
    command_not_supported = 7,
    address_type_not_supported = 8,

    pub fn from_int(i: u8) ?Reply {
        return std.enums.fromInt(Reply, i) orelse null;
    }
};

const AddressType = enum(u3) {
    ipv4 = 1,
    domain_name = 3,
    ipv6 = 4,

    pub fn from_int(i: u8) ?AddressType {
        return std.enums.fromInt(AddressType, i) orelse null;
    }
};

const Address = union(AddressType) {
    ipv4: u32,
    domain_name: []const u8,
    ipv6: u128,
};

pub fn build_commmand_failure_reply(comptime reply: Reply) [command_negotiation_failure_reply_message_size]u8 {
    assert(reply != .success);
    const rsv: u8 = 0;
    const rep: u8 = @intFromEnum(reply);
    const atyp: u8 = @intFromEnum(AddressType.ipv4);
    const bnd_port: [2]u8 = .{ 0, 0 };
    const bnd_addr: [4]u8 = .{ 0, 0, 0, 0 };
    return [_]u8{ constants.socks_version, rep, rsv, atyp } ++ bnd_addr ++ bnd_port;
}

pub fn build_command_success_reply(
    comptime addr: Address,
    port: u16,
) switch (addr) {
    .ipv4 => [command_negotiation_success_ipv4_reply_message_size]u8,
    .ipv6 => [command_negotiation_success_ipv6_reply_message_size]u8,
    else => unreachable,
} {
    assert(port > 0);
    const rsv: u8 = 0;
    const rep: u8 = @intFromEnum(Reply.success);
    const atyp: u8 = @intFromEnum(@as(AddressType, addr));
    return switch (addr) {
        .ipv4 => [_]u8{ constants.socks_version, rep, rsv, atyp } ++ std.mem.toBytes(addr.ipv4) + std.mem.toBytes(port),
        .ipv6 => [_]u8{ constants.socks_version, rep, rsv, atyp } ++ std.mem.toBytes(addr.ipv6) + std.mem.toBytes(port),
        else => unreachable,
    };
}

const failure_replies: [9][command_negotiation_failure_reply_message_size]u8 = .{
    undefined, // no build_commmand_failure_reply(.success)
    build_commmand_failure_reply(.socks_server_failure),
    build_commmand_failure_reply(.ruleset_violation),
    build_commmand_failure_reply(.network_unreachable),
    build_commmand_failure_reply(.host_unreachable),
    build_commmand_failure_reply(.connection_refused),
    build_commmand_failure_reply(.ttl_expired),
    build_commmand_failure_reply(.command_not_supported),
    build_commmand_failure_reply(.address_type_not_supported),
};

comptime {
    assert(builtin.os.tag == .linux);

    if (builtin.mode != .Debug) // Useful when experimenting locally.
        assert(std.mem.findScalar(AuthMethod, &available_auth_methods, .none) == null);

    // It makes no sense for the `.unacceptable` method to be in the available_auth_methods.
    assert(std.mem.findScalar(AuthMethod, &available_auth_methods, .gssapi) == null);
    assert(std.mem.findScalar(AuthMethod, &available_auth_methods, .unacceptable) == null);
    assert(std.mem.findScalar(AuthMethod, &available_auth_methods, .novell_directory_services_authentication) == null);
    assert(std.mem.findScalar(AuthMethod, &available_auth_methods, .challenge_response_authentication_method) == null);
    assert(std.mem.findScalar(AuthMethod, &available_auth_methods, .challenge_handshake_authentication_protocol) == null);

    // assert(std.mem.findScalar(AuthMethod, &available_auth_methods, .tls) != null);
    // assert(std.mem.findScalar(AuthMethod, &available_auth_methods, .credentials) != null);
}

const ConnectionPhase = enum {
    auth_method_negotiation,
    auth_sub_negotiation,
    // TODO: check if this one is useful for send misdirection.
    command_negotiation,
    transferring,
};

const Operation = union(enum) {
    create_socket: struct {
        domain: u32,
        socket_type: u32,
        protocol: u32,
    },
    accept: struct {
        socket: linux.fd_t,
        address: PosixAddress,
        address_size: linux.socklen_t,
    },
    read_signalfd: struct {
        fd: linux.fd_t,
        siginfo: linux.signalfd_siginfo, // buffer: []u8,
    },
    read: struct {
        fd: linux.fd_t,
        buffer: []u8,
    },
    recv: struct { // Should not be used for udp. Use recvmsg or recvmmsg.
        socket: linux.fd_t,
        buffer: []u8,
        flags: u32,

        timeout: ?struct {
            ts: linux.kernel_timespec,
            flags: u32,
        } = null,
    },
    send: struct { // Should not be used for udp. Use sendmsg or sendmmsg.
        socket: linux.fd_t,
        buffer: []const u8,
        flags: u32,

        /// NOTE: This **may** be useless.
        timeout: ?struct {
            ts: linux.kernel_timespec,
            flags: u32,
        } = null,
    },
    connect: struct {
        socket: linux.fd_t,
        address: PosixAddress,
        address_size: linux.socklen_t,

        // NOTE: Timeout is non negotiable.
        timeout: struct {
            ts: linux.kernel_timespec,
            flags: u32,
        },
    },
    close: struct {
        fd: linux.fd_t,
    },
    // shutdown_write_side: struct {
    //     socket: linux.fd_t,
    // },
    // shutdown_socket: struct { // for shutting down the socket on both ends.
    //     socket: linux.fd_t,
    // },
    shutdown: struct {
        socket: linux.fd_t,
        how: u32,
    },
    cancel_all_requests: void,
};

/// NOTE: The connection is responsible for setting its own state.
/// So the handler for any given connection is prohibited from setting the state of any other connection.
const ConnectionState = union(enum) {
    /// This holds the amount of bytes in the auth negotiation phase (stored in Connection.buffer).
    /// NOTE: The RFC states that the client's negotiation can be up to 257 bytes.
    /// In practice this is too much and 255 bytes are more than enough to represent the entire negotiation.
    /// Even a u8 is too much for a client to use entirely. The RFC's largess should be ignored.
    /// Any client sending a request of 256 bytes or more will be disconnected + banned for malicious activity.
    ///
    /// Dual use state:
    /// 1) When receiving data, it tracks how many bytes are in the auth method message sent by the client.
    /// 2) When sending data, it tracks how many bytes have been copied to the kernel for the reply.
    ///
    /// NOTE: For the second case, it's only useful to track the copied bytes in case of a tcp partial write.
    /// This is extremly unlikely to happen for a small amount of bytes, but you can never been too careful with this.
    auth_method_negotiation: u8,

    /// For credentials or TLS negotiation.
    ///
    /// TLS Handshake can have a size of up to u24 bytes.
    /// We won't tolerate that here, anything beyond 32kb will be dropped.
    auth_sub_negotiation: u16,

    /// Holds the amount of bytes in the command negotiation phase.
    command_negotiation: u9,

    // /// The next state after `command_negotiation`. This will contain the same amount of bytes as `command_negotiation`.
    // NOTE: turns out i don't need this.
    // connecting_to_server: u9,

    awaiting_udp_message,

    /// TODO: Figure out if connection_to_server should be its own state
    /// or if it should simply stay as part of the command negotiation.
    transferring,

    /// Used when an error occurs in the middle of the command negotiation phase.
    terminating_with_reply: Reply,

    /// Used when an error or disconnection occurs during the auth negotiation / command negotiation / transferring phase.
    terminating: ConnectionPhase,

    terminated,
};

const Connection = struct {
    kind: enum(u2) {
        /// For the control plane in UDP associate and data plane in CONNECT.
        client_tcp,

        server_tcp,

        client_udp,

        server_udp,
    },

    /// Relevant for encapsulation for when the server sends us data.
    /// Relevant for decapsulation for when the client sends us data.
    negotiated_auth_method: AuthMethod,

    /// TODO: Get rid of this ? The Session struct is already tagged.
    negotiated_command: Command,

    socket: linux.fd_t,

    /// When querying for the ipv4 mapping of a domain name the first 4kb
    /// will used to hold the UDP reply from the resolver.
    buffer_ptr: *[constants.max_buffer_size]u8,

    /// NOTE: Realtime clock is unreliable, and monotonic can still go backwards.
    ///
    /// Stores the amount of nanoseconds since system startup.
    established_at_ns: u64,

    traffic_stats: struct {
        bytes_in: u64 = 0,
        bytes_out: u64 = 0,
    } = .{},

    session_id: SessionId,

    state: ConnectionState,

    /// Check remote_address.any.family for address type.
    remote_address: PosixAddress,

    /// We are either receiving data from a Connection or sending the data we received from it to its peer but not both at the same time.
    /// These operations must be tied to each other for back pressure, bounded memory usage and just overall easier cleanup of inflight SQEs.
    /// TODO: document all the ways this operation gets used.
    inflight_operation: Operation,

    pub fn remote_ip_address(connection: *const Connection) u128 {
        // TODO: verify whether this is has any endianess issues....
        return switch (connection.remote_address.any.family) {
            linux.AF.INET => connection.remote_address.in.addr,
            linux.AF.INET6 => std.mem.bytesToValue(u128, &connection.remote_address.in6.addr),
            else => unreachable,
        };
    }

    pub fn port(connection: *const Connection) u16 {
        return switch (connection.remote_address.any.family) {
            linux.AF.INET => connection.remote_address.in.port,
            linux.AF.INET6 => connection.remote_address.in6.port,
            else => unreachable,
        };
    }

    pub fn socket_type(self: *const Connection) enum { tcp, udp } {
        return switch (self.kind) {
            .client_udp, .server_udp => .udp,
            .client_tcp, .server_tcp => .tcp,
        };
    }
};

const SessionId = u128;

const Session = union(enum(u1)) {
    connect: struct {
        client_tcp_data_plane: Connection,
        server_tcp_data_plane: Connection,
    },
    udp_associate: struct {
        client_udp_data_plane: Connection,
        client_tcp_control_plane: Connection,
        udp_destinations: std.ArrayListUnmanaged(Connection), // max_udp_destinations is known at runtime.
    },
};

const ProxyStats = struct {
    abrupt_connection_terminations_count: u64 = 0,
    graceful_connection_terminations_count: u64 = 0,

    median_connection_duration_ms: u64 = 0,
    average_connection_duration_ms: u64 = 0,
    maximum_connection_duration_ms: u64 = 0,

    commands_count: struct {
        bind_command_count: u64 = 0,
        connect_command_count: u64 = 0,
        udp_associate_command_count: u64 = 0,
    } = .{},

    // Keeps track of how many times each method was picked.
    authentication_methods_count: struct {
        no_auth_count: u64 = 0,
        gssapi_count: u64 = 0,
        credentials_count: u64 = 0,
        challenge_response_authentication_method_count: u64 = 0,
        challenge_handshake_authentication_protocol_count: u64 = 0,
        tls_count: u64 = 0,
        novell_directory_services_authentication_count: u64 = 0,
        unacceptable_count: u64 = 0,
    } = .{},

    peak_connections_count: u64 = 0,

    total_connections_accepted: u64 = 0,

    total_bytes_in: u64 = 0,
    total_bytes_out: u64 = 0,

    total_sqes_submitted: u64 = 0,
};

const ProxyConfig = struct {
    io_ring_size: u16 = 256,

    max_clients_count: u16 = 32,

    /// This determines how many remote udp destinations we keep track of.
    /// Newer udp destinations will evict the oldest un-used ones and take their place.
    max_udp_destinations: u8 = 32,

    // NOTE: read the NOTES part of listen(2) before modifying this.
    listen_backlog: u32 = 64,

    defer_accept_timeout_sec: ?c_int = 10,

    // TODO: add support for multiple addresses and custom ports.
    ip_address: IP_Address,

    /// TODO: Deal with SSRF(https://en.wikipedia.org/wiki/Server-side_request_forgery).
    forbidden_dst_ports: []u16,
    forbidden_dst_ipv4_addresses: []u32,
    forbidden_dst_ipv6_addresses: []u128,
    forbidden_dst_domain_names: [][]const u8,
};

const Socks5Proxy = struct {
    io_ring: IO_Uring,
    server_socket: linux.fd_t,
    time: utils.Time,
    stats: ProxyStats,
    config: ProxyConfig,
    buffer_pool: BufferPool(constants.max_buffer_size),
    udp_connection_pool: ChunkPool(Connection),

    /// NOTE: This field is also used for closing connections when the proxy is at capacity.
    /// After receiving the close CQE, we reissue another accept SQE using this field.
    accept_operation: Operation,

    read_signalfd_operation: Operation,

    /// Used for linking the client and server(s) and helps with clean up.
    session_id: SessionId,

    /// Contains sessions which finished negotiating and in which a bidirectional connection has been established.
    /// We mostly use this due to the UDP associate command.
    /// TODO: Explain why (UDP Associate requires dynamic connections).
    active_sessions: std.AutoHashMapUnmanaged(SessionId, Session),

    /// Contains clients currently in negotiation phase, i.e those which have yet to chose the desired command.
    pending_clients: std.AutoHashMapUnmanaged(linux.fd_t, Connection),

    pub fn init(proxy_config: ProxyConfig, allocator: std.mem.Allocator) !Socks5Proxy {
        const ring_flags: u32 =
            linux.IORING_SETUP_SUBMIT_ALL |
            linux.IORING_SETUP_COOP_TASKRUN |
            linux.IORING_SETUP_SINGLE_ISSUER |
            linux.IORING_SETUP_DEFER_TASKRUN;

        var io_ring = try IO_Uring.init(proxy_config.io_ring_size, ring_flags);
        errdefer io_ring.deinit();
        assert(io_ring.fd > 2);

        const io_ring_supports_no_drop: bool = (io_ring.features & linux.IORING_FEAT_NODROP) != 0;
        if (!io_ring_supports_no_drop) {
            @panic("nodrop support is required in io_uring: use kernel version >= 5.19");
        }

        // The amount of inflight negotiations can at most be equal to max_clients_count.
        // Once a client has been accepted, we must check that the sum of clients
        // in negotiation phase and active sessions is less than `max_clients_count`.
        assert(proxy_config.max_clients_count > 0);

        var pending_clients: std.AutoHashMapUnmanaged(linux.fd_t, Connection) = .empty;
        try pending_clients.ensureTotalCapacity(allocator, proxy_config.max_clients_count);
        errdefer pending_clients.deinit(allocator);

        var active_sessions: std.AutoHashMapUnmanaged(SessionId, Session) = .empty;
        try active_sessions.ensureTotalCapacity(allocator, proxy_config.max_clients_count);
        errdefer active_sessions.deinit(allocator);

        const server_socket = try io_utils.setup_server_socket(
            proxy_config.ip_address,
            proxy_config.listen_backlog,
            proxy_config.defer_accept_timeout_sec,
        );
        errdefer _ = linux.close(server_socket);
        assert(server_socket > 2);

        const signalfd = try utils.setup_signalfd(&[_]linux.SIG{
            linux.SIG.HUP, // 1: for configuration reloading
            linux.SIG.INT, // 2: graceful shutdown
            linux.SIG.TERM, // 15: graceful shutdown
        });
        errdefer _ = linux.close(signalfd);
        assert(signalfd > 2);

        const buffers_count = utils.total_buffers_count(proxy_config.max_clients_count, proxy_config.max_udp_destinations);
        var buffer_pool: BufferPool(constants.max_buffer_size) = try .init(allocator, buffers_count);
        errdefer buffer_pool.deinit(allocator);

        var udp_connection_pool: ChunkPool(Connection) = try .init(allocator, proxy_config.max_clients_count, proxy_config.max_udp_destinations);
        errdefer udp_connection_pool.deinit(allocator);

        const read_signalfd_operation = Operation{
            .read_signalfd = .{
                .fd = signalfd,
                .siginfo = std.mem.zeroInit(linux.signalfd_siginfo, .{}),
            },
        };
        const proxy = Socks5Proxy{
            .config = proxy_config,

            .server_socket = server_socket,
            .io_ring = io_ring,

            .time = .{},
            .stats = .{},

            .session_id = 0,
            .buffer_pool = buffer_pool,
            .udp_connection_pool = udp_connection_pool,
            .active_sessions = active_sessions,
            .pending_clients = pending_clients,

            .accept_operation = undefined,
            .read_signalfd_operation = read_signalfd_operation,
        };
        return proxy;
    }

    pub fn main_loop(self: *Socks5Proxy) !void {
        self.enqueue_read_signalfd();
        self.enqueue_accept_clients();
        _ = self.submit_all_no_wait() catch unreachable;

        std.log.info("proxy started: realtime={d}, monotonic_time={d}.", .{
            self.time.get_realtime(),
            self.time.monotonic_clock(),
        });
        defer std.log.info("proxy exiting: realtime={d}, monotonic_time={d}.", .{
            self.time.get_realtime(),
            self.time.monotonic_clock(),
        });

        while (true) {
            const result: anyerror!bool = self.handle_cqes();
            if (result) |should_continue| {
                // We submit the SQEs even if should_shutdown == true.
                // They get canceled in any case at the end of the while loop.
                _ = self.submit_all_no_wait() catch unreachable;
                if (should_continue) continue;
            } else |err| {
                std.log.err("handle_cqes encountered an error: {s}.", .{@errorName(err)});
            }
            // NOTE: A socks5 proxy has no insight into the bytes it transports (more or less).
            // Graceful termination is therefore impossible. Thus, we take the easy the path here,
            // simply canceling all requests, and exiting the app, the kernel will take care of the sockets tear down.
            // The requests cancelation may interrupt inflight sessions teardown. This is fine.
            //
            // TODO(IMPORTANT): Add a branch for error.CANCELED in every CQE handler.
            self.enqueue_cancel_all_requests();
            _ = self.submit_all_no_wait() catch unreachable;
            break;
        }
    }

    pub fn handle_cqes(self: *Socks5Proxy) anyerror!bool {
        var cqes: [256]linux.io_uring_cqe = undefined;
        const completions_count = try self.io_ring.copy_cqes(&cqes, 1);
        assert(completions_count > 0);

        var should_continue = true;
        for (cqes[0..completions_count]) |*completion| {
            const operation: *Operation = @ptrFromInt(completion.user_data);
            switch (operation.*) {
                .send => self.handle_send(completion),
                .recv => self.handle_recv(completion),
                .close => self.handle_close(completion),
                .accept => self.handle_accept(completion),
                .shutdown => self.handle_shutdown(completion),
                .read_signalfd => {
                    if (self.handle_read_signalfd(completion)) {
                        should_continue = false;
                        break; // We drop the next CQEs.
                    }
                },
                .cancel_all_requests => unreachable, // Should be used
                else => unreachable,
            }
        }
        return should_continue;
    }

    pub fn handle_shutdown(self: *Socks5Proxy, completion: *linux.io_uring_cqe) void {
        const operation: *Operation = @ptrFromInt(completion.user_data);
        assert(operation.* == .shutdown);
        assert(operation.shutdown.socket > 2);
        assert(operation.shutdown.how == linux.SHUT.RDWR);

        // TODO: finish
        _ = &self;
    }

    pub fn handle_close(self: *Socks5Proxy, completion: *linux.io_uring_cqe) void {
        const operation: *Operation = @ptrFromInt(completion.user_data);
        assert(operation.* == .close);
        assert(operation.close.fd >= 0);

        assert(completion.res <= 0);
        const result: ?OsError = if (completion.res == 0) null else io_utils.io_uring_error(completion.res);
        if (result) |err| {
            @branchHint(.cold);
            switch (err) {
                error.INTR => {}, // man 2 close: "close() must not be called again after an EINTR error".
                error.BADF => unreachable,
                error.NOSPC => unreachable,
                error.DQUOT => unreachable,
                error.IO => unreachable,
                else => std.log.warn("close: unknown error encountered: {any} for operation: {any}", .{ err, operation.* }),
            }
            if (err != error.INTR) {
                return;
            }
        }

        // Indicates that the `accept_operation` field was repurposed for a close operation. Usually close operations are tied to a Connection.
        // But since the proxy was at max_clients_count, then there's no place for an additional Connection, instead relying on the pre-existing field for the op.
        const rejected_client_connection = (operation == &self.accept_operation);
        if (rejected_client_connection) {
            assert(!self.pending_clients.contains(operation.close.fd));
            self.enqueue_accept_clients();
            return;
        }

        const connection: *Connection = @alignCast(@fieldParentPtr("inflight_operation", operation));
        assert(connection.state == .terminating or connection.state == .terminating_with_reply);

        // should be mirrored with a get_array_ptr_assume_capacity during connection creation.
        self.buffer_pool.put(connection.buffer_ptr);
        connection.state = .terminated;

        const active_session = self.active_sessions.getPtr(connection.session_id);
        if (active_session) |session| {
            // NOTE: this is safe: the close will be handled before the next fd returned by accept(2) is put in the pending_clients.
            assert(!self.pending_clients.contains(connection.socket));

            switch (session.*) {
                .connect => {
                    switch (connection.kind) {
                        .client_tcp => assert(connection == &session.connect.client_tcp_data_plane),
                        .server_tcp => assert(connection == &session.connect.server_tcp_data_plane),
                        else => unreachable,
                    }
                    if (session.connect.client_tcp_data_plane.state != .terminated) {
                        // Ensure that the other side also started the closing down process.
                        assert(session.connect.server_tcp_data_plane.inflight_operation == .close);
                    }
                    if (session.connect.server_tcp_data_plane.state != .terminated) {
                        assert(session.connect.client_tcp_data_plane.inflight_operation == .close);
                    }
                    if (session.connect.client_tcp_data_plane.state == .terminated and
                        session.connect.server_tcp_data_plane.state == .terminated)
                    {
                        // At this point, nothing remains. All the buffers have been put back in the pool.
                        // And the session has been deleted and file descriptors closed.
                        assert(self.active_sessions.remove(connection.session_id));
                    }
                },
                .udp_associate => {
                    switch (connection.kind) {
                        .server_udp => {
                            if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) {
                                const exists = exists: for (session.udp_associate.udp_destinations.items) |*destination| {
                                    if (destination == connection)
                                        break :exists true;
                                } else false;
                                assert(exists);
                            }
                        },
                        .client_udp => assert(connection == &session.udp_associate.client_udp_data_plane),
                        .client_tcp => assert(connection == &session.udp_associate.client_tcp_control_plane),
                        else => unreachable,
                    }
                    assert(session.udp_associate.client_udp_data_plane.inflight_operation == .close);
                    assert(session.udp_associate.client_tcp_control_plane.inflight_operation == .close);

                    // Means that all close handlers have run (includes the current function).
                    var all_terminated = true;
                    for (session.udp_associate.udp_destinations.items) |*udp_connection| {
                        assert(udp_connection.inflight_operation == .close);
                        if (udp_connection.state != .terminated)
                            all_terminated = false;
                    }

                    if (all_terminated) {
                        // TODO: free the udp_destinations.
                    }
                },
            }
        } else {
            // TODO:
        }
    }

    pub fn handle_send(self: *Socks5Proxy, completion: *linux.io_uring_cqe) void {
        const operation: *Operation = @ptrFromInt(completion.user_data);
        assert(operation.* == .send);
        assert(operation.send.socket > 2);
        assert(operation.send.buffer.len > 0);

        const connection: *Connection = @alignCast(@fieldParentPtr("inflight_operation", operation));
        assert(connection.kind == .client_tcp or connection.kind == .server_tcp);

        switch (connection.kind) {
            .client_tcp => self.handle_client_tcp_send(connection, completion),
            .server_tcp => self.handle_server_tcp_send(connection, completion),
            else => unreachable,
        }
    }

    pub fn handle_server_tcp_send(self: *Socks5Proxy, connection: *Connection, completion: *linux.io_uring_cqe) void {
        // TODO:DO
        _ = &self;
        _ = &completion;
        assert(connection.kind == .server_tcp);
    }

    pub fn handle_client_tcp_send(self: *Socks5Proxy, connection: *Connection, completion: *linux.io_uring_cqe) void {
        assert(connection.kind == .client_tcp);
        const operation: *Operation = @ptrFromInt(completion.user_data);

        // Depending on the state of the client's connection, the inflight_operation might be used
        // to send data to either the client's own socket, or the server's socket.
        // We ensure that no misdirected send happens depending on this state.
        switch (connection.state) {
            .awaiting_udp_message => assert(true), // TODO

            // All sends before session establishement are directed towards the Connection's own socket.
            .auth_method_negotiation, .auth_sub_negotiation, .command_negotiation, .terminating_with_reply => assert(connection.socket == operation.send.socket),

            // If we are terminating the transferring phase (which is when the session has been established)
            // then all the Connection's inflight sends are directed to its peer (the server in this instance).
            .terminating => |phase| switch (phase) {
                .transferring => {
                    const session: *Session = self.active_sessions.getPtr(connection.session_id).?;
                    assert(session.* == .connect); // No BIND.

                    assert(connection == &session.connect.client_tcp_data_plane);
                    assert(operation.send.socket == session.connect.server_tcp_data_plane.socket);
                },
                .auth_method_negotiation, .auth_sub_negotiation, .command_negotiation => assert(connection.socket == operation.send.socket),
            },
            .terminated, .transferring => {
                const session: *Session = self.active_sessions.getPtr(connection.session_id).?;
                assert(&session.connect.client_tcp_data_plane == connection);
                assert(operation.send.socket == session.connect.server_tcp_data_plane.socket);
            },
        }

        // Allow the first peer to encounter an error to shutdown(2) and close(2) both sockets.
        // Starting with its peer's socket, and then its own.
        // So an error in send(client_socket) issued by the server will result in the following:
        // 1) shutdown(client_socket) + client_conn.state = server_conn.state = .terminating.
        // this shutdown may end up canceling any inflight recv(client_socket) issued by the client, but not the send(server_socket).
        // 2) on shutdown_sqe(client_socket), call shutdown(server_socket), which will cancel any inflight send(server_socket).
        // TODO: document close(2)
        const session_exists_and_is_terminating = connection.state == .terminating and connection.state.terminating == .transferring;
        if (session_exists_and_is_terminating) {
            const session: *Session = self.active_sessions.getPtr(connection.session_id).?;
            assert(session.* == .connect); // No bind
            assert(&session.connect.client_tcp_data_plane == connection);
            const server_connection: *Connection = &session.connect.server_tcp_data_plane;
            assert(operation.send.socket == server_connection.socket);
            assert(server_connection.state == .terminating or server_connection.state == .terminated);
            return;
        }

        const result: OsError!usize = if (completion.res < 0) io_utils.io_uring_error(completion.res) else @intCast(completion.res);
        if (result) |bytes_sent| {
            // Not entirely related to send(2), but the UDP payload can be 0 bytes in size.
            // But socks5 has a header per udp packet which makes this case impossible when sending to the client.
            assert(bytes_sent > 0);
            switch (connection.state) {
                .auth_method_negotiation => |bytes_so_far| {
                    const auth_method_index = std.mem.findScalar(AuthMethod, &available_auth_methods, connection.negotiated_auth_method);
                    assert(auth_method_index != null);
                    assert(connection.negotiated_command == .none);

                    const total_auth_negotiation_bytes_sent = bytes_so_far + bytes_sent;
                    assert(total_auth_negotiation_bytes_sent <= auth_method_negotiation_reply_message_size);

                    const sent_all_auth_reply_bytes = total_auth_negotiation_bytes_sent == auth_method_negotiation_reply_message_size;
                    defer {
                        // State either changed, or remained the same but the bytes sent were incremented.
                        if (sent_all_auth_reply_bytes)
                            assert((connection.state == .command_negotiation and connection.state.command_negotiation == 0) or
                                (connection.state == .auth_sub_negotiation and connection.state.auth_sub_negotiation == 0))
                        else
                            assert(connection.state == .auth_method_negotiation and connection.state.auth_method_negotiation > bytes_so_far);
                    }
                    if (sent_all_auth_reply_bytes) {
                        @branchHint(.likely);
                        switch (connection.negotiated_auth_method) {
                            // TODO
                            .tls => {
                                connection.state = .{ .auth_sub_negotiation = 0 };
                            },
                            // TODO:
                            // Requires implementing (or stealing) an SPMC for the `io_ring` owning thread
                            // to delegate the hashing to the many consumer threads.
                            // This would also probably require usage of eventfd.
                            // Alternatively I could just use md5 hashing and call it a day.
                            .credentials => {
                                connection.state = .{ .auth_sub_negotiation = 0 };
                                const auth_sub_negotiation_deadline_ns: u64 =
                                    connection.established_at_ns + (constants.max_credentials_method_sub_negotiation_deadline_sec * std.time.ns_per_s);

                                self.enqueue_connection_recv(
                                    connection,
                                    .{
                                        .ts = .{
                                            .sec = @intCast(auth_sub_negotiation_deadline_ns / std.time.ns_per_s),
                                            .nsec = @intCast(auth_sub_negotiation_deadline_ns % std.time.ns_per_s),
                                        },
                                        .flags = linux.IORING_TIMEOUT_ABS | linux.IORING_TIMEOUT_BOOTTIME,
                                    },
                                );
                            },

                            .none => {
                                connection.state = .{ .command_negotiation = 0 };
                                const command_negotiation_deadline_ns: u64 =
                                    connection.established_at_ns + (constants.max_command_negotiation_deadline_sec * std.time.ns_per_s);

                                self.enqueue_connection_recv(
                                    connection,
                                    .{
                                        .ts = .{
                                            .sec = @intCast(command_negotiation_deadline_ns / std.time.ns_per_s),
                                            .nsec = @intCast(command_negotiation_deadline_ns % std.time.ns_per_s),
                                        },
                                        .flags = linux.IORING_TIMEOUT_ABS | linux.IORING_TIMEOUT_BOOTTIME,
                                    },
                                );
                            },

                            else => unreachable,
                        }
                    } else {
                        connection.state.auth_method_negotiation += @intCast(bytes_sent);
                        assert(operation.send.buffer[bytes_sent..].len > 0);

                        const send_flags = 0;
                        const no_timeout = null;
                        self.enqueue_socket_send(
                            &connection.inflight_operation,
                            connection.socket,
                            operation.send.buffer[bytes_sent..],
                            send_flags,
                            no_timeout,
                        );
                    }
                },
                .terminating => |connection_phase| {
                    switch (connection_phase) {
                        // NOTE: We don't care about short writes here. They are extremely unlikely to occur in any case since both
                        // `unacceptable_auth_method_reply_message` and `credentials_sub_negotiation_failure_reply_message` are 2 bytes each
                        // and because we close the connection right afterwards anyways.
                        // I'm *almost* tempted to assert on the `bytes_sent` being equal to the length of either of those...
                        .auth_method_negotiation => {
                            assert(operation.send.buffer.ptr == &unacceptable_auth_method_reply_message);
                            if (bytes_sent < unacceptable_auth_method_reply_message.len) {
                                // Would be miraculous if this branch is ever reached that's why I'm using log.warn()
                                std.log.warn("client(ip={d}, port={d}): unlikely tcp short write during auth method negotiation.", .{
                                    connection.remote_ip_address(),
                                    connection.port(),
                                });
                            }
                            self.enqueue_connection_close(connection);
                        },
                        .auth_sub_negotiation => {
                            assert(operation.send.buffer.ptr == &credentials_sub_negotiation_failure_reply_message);
                            if (bytes_sent < credentials_sub_negotiation_failure_reply_message.len) {
                                // Would be miraculous if this branch is ever reached that's why I'm using log.warn()
                                std.log.warn("client(ip={d}, port={d}): unlikely tcp short write during credentials sub_negotiation.", .{
                                    connection.remote_ip_address(),
                                    connection.port(),
                                });
                            }
                            self.enqueue_connection_close(connection);
                        },
                        // TODO: finish
                        .command_negotiation => {},
                        .transferring => {},
                    }
                },
                .command_negotiation => {},
                .transferring => {
                    assert(connection.negotiated_command != .none);
                    assert(!self.pending_clients.contains(connection.socket));
                    assert(operation.send.timeout == null);

                    const session: *Session = self.active_sessions.getPtr(connection.session_id).?;
                    assert(session.* == .connect);
                    assert(operation.send.socket == session.connect.server_tcp_data_plane.socket);
                    // TODO: handle rest
                    // TODO: verify whether this status enum is ever needed.
                    // switch (session.status) {
                    //     .active => {
                    //         const is_short_send = bytes_sent != operation.send.buffer.len;
                    //         if (is_short_send) {
                    //             const no_timeout = null;
                    //             self.enqueue_socket_send(
                    //                 &connection.inflight_operation,
                    //                 operation.send.socket,
                    //                 operation.send.buffer[bytes_sent..],
                    //                 operation.send.flags,
                    //                 no_timeout,
                    //             );
                    //         } else {
                    //             const recv_flags = 0;
                    //             const no_timeout = null;
                    //             self.enqueue_socket_recv(
                    //                 &connection.inflight_operation,
                    //                 connection.socket,
                    //                 connection.buffer_ptr,
                    //                 recv_flags,
                    //                 no_timeout,
                    //             );
                    //         }
                    //     },
                    //     .terminating => {},
                    // }
                },
                else => {},
            }
        } else |err| {
            switch (err) {
                error.CANCELED => return, // We just drop everything.

                error.ACCES, error.AGAIN, error.ALREADY, error.BADF, error.DESTADDRREQ, error.FAULT, error.INTR, error.INVAL, error.ISCONN, error.MSGSIZE, error.NOTCONN, error.NOTSOCK, error.OPNOTSUPP => unreachable,

                error.NOBUFS, error.NOMEM => {
                    // TODO: handle
                },

                error.PIPE, error.CONNRESET => {
                    // defer assert(connection.state != .transferring);
                    
                    // NOTE: We can't be certain about what caused an EPIPE error as it's inherently racy.
                    // So checking that this connection is part of a session and that the other peer forced a shutdown is futile.
                    // What matters is that clean up be executed.
                    // NOTE: usage of shutdown(2) is inherently racy in any case.
                    if (self.active_sessions.getPtr(connection.session_id)) |session| {
                        assert(session.* == .connect); // NOTE: We don't use BIND, so assert that it's a CONNECT.
                        assert(connection.state == .transferring);
                        assert(connection.negotiated_command != .none);
                        assert(!self.pending_clients.contains(connection.socket));

                        session.connect.client_tcp_data_plane.state = .{ .terminating = .transferring };
                        session.connect.server_tcp_data_plane.state = .{ .terminating = .transferring };
                        self.enqueue_shutdown(
                            &connection.inflight_operation,
                            session.connect.server_tcp_data_plane.socket,
                            linux.SHUT.RDWR,
                        );
                    } else {
                        switch (connection.state) {
                            .auth_method_negotiation, .auth_sub_negotiation, .command_negotiation => {
                                std.log.debug("client(ip={d}, port={d}): encountered send error during {any}: {s}.", .{
                                    connection.remote_ip_address(),
                                    connection.port(),
                                    connection.state,
                                    @errorName(err),
                                });
                                connection.state = .{ .terminating = switch (connection.state) {
                                    .auth_method_negotiation => .auth_method_negotiation,
                                    .auth_sub_negotiation => .auth_sub_negotiation,
                                    .command_negotiation => .command_negotiation,
                                    else => unreachable,
                                } };
                                self.enqueue_connection_close(connection);
                            },
                            .terminating_with_reply => |reply| {
                                assert(reply != .success);
                                std.log.debug("client(ip={d}, port={d}): encountered send error while replying to command request: {s}.", .{
                                    connection.remote_ip_address(),
                                    connection.port(),
                                    @errorName(err),
                                });
                                self.enqueue_connection_close(connection);
                            },

                            // This state is only used for coordinating the shutdown of a session.
                            // Not of individual clients in negotiation.
                            .terminated => unreachable,
                            .awaiting_udp_message => unreachable,

                            // Being in a `terminating` state during any phase should prevent us from reaching
                            // the send handler.
                            // If `terminating` is set during a negotiation, we shouldn't reach this send handler,
                            // we should be issuing a close(2) and calling the handler for its CQE.
                            //
                            // If this is set after the session has been established, then the session should exist
                            // in the hash_map lookup in the previous branch.
                            .terminating => unreachable,

                            // This state may only be reached when a session exists.
                            .transferring => unreachable,
                        }
                    }
                },

                else => {
                    // TODO: Handle other send errors.
                },
            }
        }
    }

    pub fn handle_recv(self: *Socks5Proxy, completion: *linux.io_uring_cqe) void {
        const operation: *Operation = @ptrFromInt(completion.user_data);
        assert(operation.* == .recv);
        assert(operation.recv.socket > 2);
        assert(operation.recv.buffer.len > 0);

        // NOTE: The alignement of an Operation is lower than that of the Connection which embeds it, so although we are certain
        // that Operation(s) are embedded within Connection(s) we still have to ensure to the compiler that the result of subtracting
        // the Operation's offset (relative to the Connection) from its address will result in an aligned Connection address.
        const connection: *Connection = @alignCast(@fieldParentPtr("inflight_operation", operation));
        assert(connection.kind == .client_tcp or connection.kind == .server_tcp);

        //
        const is_misdirected_receive = operation.recv.socket != connection.socket;
        assert(!is_misdirected_receive);

        switch (connection.kind) {
            .client_tcp => self.handle_client_tcp_receive(connection, completion),
            .server_tcp => self.handle_server_tcp_receive(connection, completion),
            else => unreachable, // For UDP, use recvmsg / recvmmsg.
        }
    }

    pub fn handle_client_tcp_receive(self: *Socks5Proxy, connection: *Connection, completion: *linux.io_uring_cqe) void {
        assert(connection.kind == .client_tcp);
        assert(connection.inflight_operation == .recv);

        const result: OsError!usize = if (completion.res < 0)
            io_utils.io_uring_error(completion.res)
        else
            @intCast(completion.res);

        if (result) |bytes_received| {
            std.log.debug("client(ip={d}, port={d}): sent bytes: {d}.", .{
                connection.remote_ip_address(),
                connection.port(),
                bytes_received,
            });
            if (bytes_received > 0) {
                switch (connection.state) {
                    .auth_method_negotiation => |bytes_so_far| {
                        assert(connection.negotiated_command == .none);
                        assert(connection.negotiated_auth_method == .none);
                        assert(self.pending_clients.contains(connection.socket));
                        assert(!self.active_sessions.contains(connection.session_id));

                        const total_auth_negotiation_bytes_received = bytes_so_far + bytes_received;
                        if (total_auth_negotiation_bytes_received <= auth_method_negotiation_request_message_max_size) {
                            connection.state.auth_method_negotiation = @intCast(bytes_received);
                            self.handle_client_auth_method_negotiation(connection);
                        } else {
                            // TODO: rate limit / ban.
                            std.log.debug("client(ip={d}, port={d}): sent too many bytes during auth method negotiation.", .{
                                connection.remote_ip_address(),
                                connection.port(),
                            });
                            connection.state = .{ .terminating = .auth_method_negotiation };
                            self.enqueue_connection_close(connection);
                        }
                    },

                    .auth_sub_negotiation => |bytes_so_far| {
                        assert(connection.negotiated_command == .none);
                        assert(connection.negotiated_auth_method != .none);
                        assert(self.pending_clients.contains(connection.socket));
                        assert(!self.active_sessions.contains(connection.session_id));

                        const total_sub_negotiation_bytes_received = bytes_so_far + bytes_received;
                        switch (connection.negotiated_auth_method) {
                            .credentials => {
                                // NOTE: It is possible to use MSG_WAITALL to wait for the minimum viable size amount of bytes.
                                if (total_sub_negotiation_bytes_received <= credentials_sub_negotiation_request_message_max_size) {
                                    connection.state.auth_sub_negotiation += @intCast(bytes_received);
                                    self.handle_client_credentials_sub_negotiation(connection);
                                } else {
                                    std.log.debug("client(ip={d}, port={d}): sent too many bytes during auth method negotiation.", .{
                                        connection.remote_ip_address(),
                                        connection.port(),
                                    });
                                    connection.state = .{ .terminating = .auth_sub_negotiation };
                                    self.enqueue_connection_close(connection);
                                }
                            },

                            .tls => {
                                // TODO: Does credentials_sub_negotiation_request_message_max_size apply here?
                                // u9 allows storing 511 bytes, is that enough for a command request that was encrypted using tls?
                            },

                            else => unreachable,
                        }
                    },
                    .command_negotiation => |bytes_so_far| {
                        assert(connection.negotiated_command == .none);
                        assert(self.pending_clients.contains(connection.socket));
                        assert(!self.active_sessions.contains(connection.session_id));

                        switch (connection.negotiated_auth_method) {
                            .none, .credentials => {
                                // NOTE: It is possible to use MSG_WAITALL to wait for the minimum viable size amount of bytes.
                                const total_command_negotiation_bytes_received = bytes_so_far + bytes_received;
                                if (total_command_negotiation_bytes_received <= command_negotiation_request_message_max_size) {
                                    connection.state.command_negotiation += @intCast(bytes_received);
                                    self.handle_client_command_negotiation(connection);
                                } else {
                                    std.log.debug("client(ip={d}, port={d}): sent too many bytes during command negotiation.", .{
                                        connection.remote_ip_address(),
                                        connection.port(),
                                    });
                                    connection.state = .{ .terminating = .command_negotiation };
                                    self.enqueue_connection_close(connection);
                                }
                            },
                            .tls => {
                                // decrypt in place before calling handle_client_command_negotiation?
                                // how to do deal with short receives?
                                unreachable;
                            },
                            else => {},
                        }
                    },

                    .transferring => {
                        assert(connection.negotiated_command != .none);
                        assert(!self.pending_clients.contains(connection.socket));

                        // TODO: Transfer bytes to server.
                        const session: *Session = self.active_sessions.getPtr(connection.session_id).?;
                        switch (session.*) {
                            .connect => |*tcp_session| {
                                assert(tcp_session.server_tcp_data_plane.kind == .server_tcp);
                                assert(tcp_session.server_tcp_data_plane.session_id == connection.session_id);
                                // TODO: Finish
                                // switch (tcp_session.status) {
                                //     .active => {
                                //         switch (connection.negotiated_auth_method) {
                                //             .none, .credentials => {
                                //                 const send_flags = 0;
                                //                 const no_timeout = null;
                                //                 self.enqueue_socket_send(
                                //                     &connection.inflight_operation,
                                //                     tcp_session.server_tcp_data_plane.socket,
                                //                     connection.buffer_ptr[0..bytes_received],
                                //                     send_flags,
                                //                     no_timeout,
                                //                 );
                                //             },
                                //             .tls => {}, // TODO: unwrap data before sending it to the server. (what about short recv?).
                                //             else => unreachable,
                                //         }
                                //     },
                                //     .terminating => {
                                //         // TODO: use the client's inflight operation to cancel the server's inflight operation ?
                                //         // (server_tcp_recv == 0) and (client_tcp_recv == 0)
                                //     },
                                // }
                            },
                            .udp_associate => |*udp_session| {
                                // It is an error for the client control plane tcp socket to send us bytes.
                                // It should only call close(2) on its socket to signal EOF which gets handled in the (bytes_received == 0) branch.
                                std.log.debug("client(ip={d}, port={d}): tcp non zero receive on control plane socket.", .{
                                    connection.remote_ip_address(),
                                    connection.port(),
                                });
                                // TODO: terminate udp session
                                _ = &udp_session;
                            },
                        }
                    },

                    // TODO: implement transferring phase
                    else => unreachable,
                }
            } else {
                // NOTE: Although this could be a TCP half close, we simply tear down everything associated with this client.
                // Clients that care about half close type of behaviour should use appropriate protocols implementing such a feature.
                self.handle_disconnection(connection);
                return;
            }
        } else |err| {
            _ = &err;
        }
        // const recv_operation: *Operation = connection.inflight_operation.recv.buffer[0..]
    }

    pub fn handle_disconnection(self: *Socks5Proxy, connection: *Connection) void {
        _ = self;
        _ = connection;
    }

    pub fn handle_client_command_negotiation(self: *Socks5Proxy, connection: *Connection) void {
        assert(connection.kind == .client_tcp);
        assert(connection.state == .command_negotiation);
        assert(connection.state.command_negotiation > 0);

        const command_negotiation_bytes = connection.buffer_ptr[0..connection.state.command_negotiation];
        const command_request = parse_command_negotiation_request(command_negotiation_bytes) catch |err| {
            switch (err) {
                error.NotEnoughBytes => {
                    const command_negotiation_deadline_ns: u64 =
                        connection.established_at_ns + (constants.max_command_negotiation_deadline_sec * std.time.ns_per_s);

                    const recv_flags = 0;
                    self.enqueue_socket_recv(
                        &connection.inflight_operation,
                        connection.socket,
                        connection.buffer_ptr[connection.state.command_negotiation..],
                        recv_flags,
                        .{
                            .ts = .{
                                .sec = @intCast(command_negotiation_deadline_ns / std.time.ns_per_s),
                                .nsec = @intCast(command_negotiation_deadline_ns % std.time.ns_per_s),
                            },
                            .flags = linux.IORING_TIMEOUT_ABS | linux.IORING_TIMEOUT_BOOTTIME,
                        },
                    );
                },
                else => {
                    std.log.debug("client(ip={d}, port={d}): command negotiation error: {s}", .{
                        connection.remote_ip_address(),
                        connection.port(),
                        @errorName(err),
                    });
                    connection.state = .{ .terminating = .command_negotiation };
                    self.enqueue_connection_close(connection);
                },
            }
            return;
        };

        if (self.validate_command_request(connection, command_request)) |err| {
            defer assert(connection.state == .terminating_with_reply);
            switch (err) {
                error.BindCommandNotSupported => {
                    self.enqueue_connection_reply_for_termination(connection, .command_not_supported);
                },
                error.AddressTypeNotSupported => {
                    self.enqueue_connection_reply_for_termination(connection, .address_type_not_supported);
                },
                error.ForbiddenPort, error.Forbidden_IPV4_Address, error.Forbidden_IPV6_Address, error.ForbiddenDomainName => {
                    self.enqueue_connection_reply_for_termination(connection, .ruleset_violation);
                },
                error.Invalid_UDP_Source => {
                    std.log.debug("client(ip={d}, port={d}): used invalid dst.addr and/or dst.port for the udp association.", .{
                        connection.remote_ip_address(),
                        connection.port(),
                    });
                    self.enqueue_connection_reply_for_termination(connection, .ruleset_violation);
                },
            }
            return;
        }

        self.handle_client_command_request(connection, command_request);
    }

    pub fn handle_client_command_request(self: *Socks5Proxy, connection: *Connection, command_request: CommandRequest) void {
        assert(connection.kind == .client_tcp);
        assert(connection.state == .command_negotiation);

        if (command_request.destination_address == .domain_name) {
            assert(command_request.command != .udp_associate);
            // Check DNS cache. If TTL expired, or no entry, then send a DNS query.
            return;
        }

        switch (command_request.command) {
            .udp_associate => {
                assert(command_request.destination_port() == 0 and command_request.destination_ip_address() == 0);
                const domain = command_request.address_family();
                const socket_type = linux.SOCK.DGRAM;
                const protocol = linux.IPPROTO.UDP;
                self.enqueue_create_socket(
                    &connection.inflight_operation,
                    domain,
                    socket_type,
                    protocol,
                );
            },
            .connect => {
                assert(command_request.destination_port() > 0);
                const domain = command_request.address_family();
                const socket_type = linux.SOCK.STREAM;
                const protocol = linux.IPPROTO.TCP;
                self.enqueue_create_socket(
                    &connection.inflight_operation,
                    domain,
                    socket_type,
                    protocol,
                );
            },
            .bind => unreachable,
            .none => unreachable,
        }
    }

    const CommandValidationError = error{
        /// BIND will never be supported.
        BindCommandNotSupported,
        AddressTypeNotSupported,

        ForbiddenDomainName,
        Forbidden_IPV4_Address,
        Forbidden_IPV6_Address,
        ForbiddenPort,

        // DST.ADDR and DST.PORT must be zero in the UDP Associate.
        Invalid_UDP_Source,
    };

    pub fn validate_command_request(self: *Socks5Proxy, connection: *Connection, command_request: CommandRequest) ?CommandValidationError {
        assert(connection.kind == .client_tcp);

        // NOTE: For now we reject all addresses of type domain name.
        // TODO: Remove this domain_name address type check.
        if (command_request.command == .bind) return error.BindCommandNotSupported;
        if (command_request.destination_address == .domain_name) return error.AddressTypeNotSupported;

        if (command_request.command == .udp_associate) {
            if (command_request.destination_address == .domain_name)
                return error.AddressTypeNotSupported;
        }

        const is_forbidden_port = std.mem.findScalar(u16, self.config.forbidden_dst_ports, command_request.destination_port()) != null;
        if (is_forbidden_port) return error.ForbiddenPort;

        // TODO: validate which ipv4 / ipv6 is allowed (block loopback and private ip addresses as well as possible cloud metadata IPs).
        // TODO: after each DNS reply, rerun this section of the code on the ipv4/ipv6 addresses. (should be its own function tbh validate_ip(type, ip)).
        switch (command_request.destination_address) {
            .domain_name => |domain_info| {
                for (self.config.forbidden_dst_domain_names) |forbidden_domain_name| {
                    const is_forbidden = std.mem.eql(u8, domain_info.fqdn, forbidden_domain_name);
                    if (is_forbidden)
                        return error.ForbiddenDomainName;
                }
            },
            .posix_address => |*posix_address| {
                switch (posix_address.any.family) {
                    linux.AF.INET => {
                        const is_forbidden_address =
                            std.mem.findScalar(u32, self.config.forbidden_dst_ipv4_addresses, posix_address.in.addr) != null;
                        if (is_forbidden_address)
                            return error.Forbidden_IPV4_Address;

                        if (command_request.command == .udp_associate) {
                            const is_valid_source_address = posix_address.in.addr == 0 and posix_address.in.port == 0;
                            if (!is_valid_source_address)
                                return error.Invalid_UDP_Source;
                        }
                    },
                    linux.AF.INET6 => {
                        const address = std.mem.readInt(u128, &posix_address.in6.addr, .big);
                        const is_forbidden_address = std.mem.findScalar(u128, self.config.forbidden_dst_ipv6_addresses, address) != null;
                        if (is_forbidden_address)
                            return error.Forbidden_IPV6_Address;

                        if (command_request.command == .udp_associate) {
                            const is_valid_source_address = address == 0 and posix_address.in6.port == 0;
                            if (!is_valid_source_address)
                                return error.Invalid_UDP_Source;
                        }
                    },
                    else => unreachable,
                }
            },
        }

        return null;
    }

    pub fn handle_client_credentials_sub_negotiation(self: *Socks5Proxy, connection: *Connection) void {
        assert(connection.kind == .client_tcp);
        assert(connection.state == .auth_sub_negotiation);
        assert(connection.state.auth_sub_negotiation > 0);

        const credentials_bytes = connection.buffer_ptr[0..connection.state.auth_sub_negotiation];
        const credentials = parse_and_validate_credentials_sub_negotiation_request(credentials_bytes) catch |err| {
            switch (err) {
                error.NotEnoughBytes => {
                    const auth_sub_negotiation_deadline_ns: u64 =
                        connection.established_at_ns + (constants.max_credentials_method_sub_negotiation_deadline_sec * std.time.ns_per_s);

                    const recv_flags = 0;
                    self.enqueue_socket_recv(
                        &connection.inflight_operation,
                        connection.socket,
                        connection.buffer_ptr[connection.state.auth_sub_negotiation..],
                        recv_flags,
                        .{
                            .ts = .{
                                .sec = @intCast(auth_sub_negotiation_deadline_ns / std.time.ns_per_s),
                                .nsec = @intCast(auth_sub_negotiation_deadline_ns % std.time.ns_per_s),
                            },
                            .flags = linux.IORING_TIMEOUT_ABS | linux.IORING_TIMEOUT_BOOTTIME,
                        },
                    );
                },
                else => {
                    std.log.debug("client(ip={d}, port={d}): credentials subnegotiation error: {s}", .{
                        connection.remote_ip_address(),
                        connection.port(),
                        @errorName(err),
                    });
                    connection.state = .{ .terminating = .auth_sub_negotiation };
                    const send_flags = 0;
                    const no_timeout = null;
                    self.enqueue_socket_send(
                        &connection.inflight_operation,
                        connection.socket,
                        &credentials_sub_negotiation_failure_reply_message,
                        send_flags,
                        no_timeout,
                    );
                },
            }
            return;
        };
        assert(credentials.username.len > 0);
        assert(credentials.password.len > 0);

        // Have a few threads which will do the CPU intensive hashing and notify the ring about the result.
        // SessionId -> Password_Hash.
    }

    pub fn handle_client_auth_method_negotiation(self: *Socks5Proxy, connection: *Connection) void {
        assert(connection.kind == .client_tcp);
        assert(connection.state == .auth_method_negotiation);
        assert(connection.state.auth_method_negotiation > 0);

        const method_negotiation_bytes = connection.buffer_ptr[0..connection.state.auth_method_negotiation];
        const client_methods: []const AuthMethod = parse_auth_method_negotiation_request(method_negotiation_bytes) catch |err| {
            switch (err) {
                error.NotEnoughBytes => {
                    const recv_flags = 0;
                    const auth_deadline_ns: u64 = connection.established_at_ns + (constants.max_auth_negotiation_deadline_sec * std.time.ns_per_s);
                    self.enqueue_socket_recv(
                        &connection.inflight_operation,
                        connection.socket,
                        connection.buffer_ptr[connection.state.auth_method_negotiation..],
                        recv_flags,
                        .{
                            .ts = .{
                                .sec = @intCast(auth_deadline_ns / std.time.ns_per_s),
                                .nsec = @intCast(auth_deadline_ns % std.time.ns_per_s),
                            },
                            .flags = linux.IORING_TIMEOUT_ABS | linux.IORING_TIMEOUT_BOOTTIME,
                        },
                    );
                },
                else => {
                    std.log.debug("client(ip={d}, port={d}): auth negotiation error: {s}", .{
                        connection.remote_ip_address(),
                        connection.port(),
                        @errorName(err),
                    });
                    connection.state = .{ .terminating = .auth_method_negotiation };
                    self.enqueue_connection_close(connection);
                },
            }
            return;
        };
        assert(client_methods.len > 0);
        std.log.debug("client(ip={d}, port={d}): sent methods: {any}.", .{
            connection.remote_ip_address(),
            connection.port(),
            client_methods,
        });

        const available_method: ?AuthMethod = auth_method: for (available_auth_methods) |auth_method| {
            const method_is_available =
                std.mem.findScalar(AuthMethod, client_methods, auth_method) != null;

            if (method_is_available) break :auth_method auth_method;
        } else null;

        if (available_method) |auth_method| {
            self.handle_client_auth_method(connection, auth_method);
        } else {
            self.handle_client_auth_method(connection, .unacceptable);
        }
    }

    pub fn handle_client_auth_method(self: *Socks5Proxy, connection: *Connection, auth_method: AuthMethod) void {
        assert(connection.kind == .client_tcp);
        assert(connection.state == .auth_method_negotiation);
        assert(connection.state.auth_method_negotiation > 0);
        defer assert(connection.state == .terminating or
            connection.state.auth_method_negotiation == 0);

        const auth_negotiation_reply: []const u8 = switch (auth_method) {
            .tls => &accepted_tls_method_reply_message,
            .none => &accepted_none_method_reply_message,
            .credentials => &accepted_credentials_method_reply_message,
            .unacceptable => &unacceptable_auth_method_reply_message,

            // We should not reach this branch as we've already checked the available_methods before calling this function.
            else => panic("client(ip={d}, port={d}): sent invalid auth_method: {d}.", .{ connection.remote_ip_address(), connection.port(), auth_method }),
        };

        std.log.debug("client(ip={d}, port={d}): sending auth_method: {any}", .{ connection.remote_ip_address(), connection.port(), auth_method });

        if (auth_method != .unacceptable) {
            connection.negotiated_auth_method = auth_method;
            // Although we could now use the state to track the amount of bytes sent in the reply to deal with TCP short writes.
            // we simply close the connection after any amount of reply bytes are sent, as it is unlikely for a TCP short write to occur.
            connection.state = .{ .auth_method_negotiation = 0 };
        } else {
            // TODO: We must match this state in the handle_client_send and tear down connection.
            connection.state = .{ .terminating = .auth_method_negotiation };
        }

        const send_flags = 0;
        const no_timeout = null;
        self.enqueue_socket_send(
            &connection.inflight_operation,
            connection.socket,
            auth_negotiation_reply,
            send_flags,
            no_timeout,
        );
    }

    pub fn handle_server_tcp_receive(self: *Socks5Proxy, connection: *Connection, completion: *linux.io_uring_cqe) void {
        assert(connection.kind == .server_tcp);
        _ = self;
        _ = completion;
    }

    pub fn handle_accept(self: *Socks5Proxy, completion: *linux.io_uring_cqe) void {
        const operation: *Operation = @ptrFromInt(completion.user_data);
        assert(operation.* == .accept);
        assert(operation.accept.socket == self.server_socket);
        assert(operation.accept.address_size == io_utils.get_address_length(&self.config.ip_address));

        const result: OsError!linux.fd_t = if (completion.res < 0)
            io_utils.io_uring_error(completion.res)
        else
            completion.res;

        if (result) |client_socket| {
            const clients_count = self.active_sessions.count() + self.pending_clients.count();
            assert(clients_count <= self.config.max_clients_count);

            if (clients_count < self.config.max_clients_count) {
                self.handle_new_client(client_socket, operation.accept.address);
            } else {
                self.enqueue_close_fd(&self.accept_operation, client_socket);
            }
        } else |err| {
            _ = &err;
            // TODO: Inspect accept4(2) failures and how to restart the listener.
            // TODO: handle error
        }
    }

    pub fn handle_read_signalfd(self: *Socks5Proxy, completion: *linux.io_uring_cqe) bool {
        const operation: *Operation = @ptrFromInt(completion.user_data);
        assert(operation.* == .read_signalfd);
        assert(operation.read_signalfd.fd > 2);

        const result: OsError!usize = if (completion.res < 0)
            io_utils.io_uring_error(completion.res)
        else
            @intCast(completion.res);

        // TODO: Implement graceful termination and config reloading.
        // TODO: Should the signal be the last thing to be processed?
        if (result) |bytes_read| {
            assert(@sizeOf(linux.signalfd_siginfo) == bytes_read);
            const signal: linux.SIG = @enumFromInt(operation.read_signalfd.siginfo.signo);
            switch (signal) {
                linux.SIG.INT, linux.SIG.TERM => {
                    std.log.warn("signalfd: received {any}.", .{signal});
                    return true;
                },
                linux.SIG.HUP => {
                    std.log.warn("signalfd: received SIGHUP.", .{});
                    // TODO: add handler.
                    return false;
                },
                else => {
                    std.log.warn("signalfd: add handler for signal: {any}.", .{signal});
                    return false;
                },
            }
        } else |err| {
            switch (err) {
                error.BADF => {
                    // Maybe this should be a call to std.debug.panic ?
                    std.log.warn("signalfd: file descriptor was closed.", .{});
                    return true;
                },
                else => {
                    // TODO: Explore what other errors might show up.
                    std.log.err("signalfd: caught an unknown error: {s}", .{@errorName(err)});
                },
            }
        }
        self.enqueue_read_signalfd();
        return false;
    }

    pub fn handle_new_client(self: *Socks5Proxy, client_socket: linux.fd_t, remote_address: PosixAddress) void {
        assert(client_socket > 2);
        const established_at_ns = self.time.monotonic_clock();

        const session_id: SessionId = self.next_session_id();
        assert(!self.pending_clients.contains(client_socket));
        assert(!self.active_sessions.contains(session_id));
        defer assert(self.pending_clients.contains(client_socket));

        if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) {
            // TODO: assert(SO_TYPE == TCP)
        }

        const buffer_ptr = self.buffer_pool.get_array_ptr_assume_capacity();
        const client_connection = Connection{
            .kind = .client_tcp,
            .negotiated_auth_method = .none,
            .negotiated_command = .none,
            .socket = client_socket,
            .buffer_ptr = buffer_ptr,
            .established_at_ns = established_at_ns,
            .traffic_stats = .{},
            .session_id = session_id,
            .state = .{ .auth_method_negotiation = 0 },
            .remote_address = remote_address,
            .inflight_operation = undefined,
        };
        self.pending_clients.putAssumeCapacity(client_socket, client_connection);

        std.log.debug("client(ip={d}, port={d}): session_id={d}, established_at={d}.", .{
            client_connection.remote_ip_address(),
            client_connection.port(),
            session_id,
            established_at_ns,
        });

        const client_connection_ptr: *Connection = self.pending_clients.getPtr(client_socket).?;
        const auth_deadline_ns: u64 = established_at_ns + (constants.max_auth_negotiation_deadline_sec * std.time.ns_per_s);
        self.enqueue_connection_recv(
            client_connection_ptr,
            .{
                .ts = .{
                    .sec = @intCast(auth_deadline_ns / std.time.ns_per_s),
                    .nsec = @intCast(auth_deadline_ns % std.time.ns_per_s),
                },
                .flags = linux.IORING_TIMEOUT_ABS | linux.IORING_TIMEOUT_BOOTTIME,
            },
        );
    }

    pub fn enqueue_shutdown(self: *Socks5Proxy, operation: *Operation, socket: linux.fd_t, how: u32) void {
        assert(socket > 2);
        assert(how == linux.SHUT.RD or how == linux.SHUT.WR or how == linux.SHUT.RDWR);
        operation.* = .{ .shutdown = .{
            .socket = socket,
            .how = how,
        } };
        const user_data: u64 = @intFromPtr(operation);
        _ = self.io_ring.shutdown(user_data, socket, how) catch {
            warn_submission_queue_full(.shutdown);
            _ = self.submit_all_no_wait() catch unreachable;
            _ = self.io_ring.shutdown(user_data, socket, how) catch unreachable;
        };
    }

    /// Difficult to do this properly, there's many issues with this and things to figure out:
    /// Can this cancel a close(2) / shutdown(2) operation ? Does it matter if we're shutting down anyway?
    /// If we encounter a SIGTERM/SIGINT in the middle of the CQEs array, do we ignore the later CQEs ?
    pub fn enqueue_cancel_all_requests(self: *Socks5Proxy) void {
        // NOTE: we repurpose the `read_signalfd_operation` field for canceling
        // all requests after receiving a signal like SIGTERM / SIGINT.
        self.read_signalfd_operation = .{ .cancel_all_requests = {} };

        const user_data: u64 = @intFromPtr(&self.read_signalfd_operation);
        // Can be any value since we're targetting ANY inflight submission.
        const cancel_user_data: u64 = 6_7;
        const cancel_flags: u32 = linux.IORING_ASYNC_CANCEL_ANY;

        // The reason I use unreachable here is because I assume that this function's called right after a call to submit_all_no_wait().
        _ = self.io_ring.cancel(user_data, cancel_user_data, cancel_flags) catch unreachable;
    }

    pub fn enqueue_create_socket(self: *Socks5Proxy, operation: *Operation, domain: u32, socket_type: u32, protocol: u32) void {
        assert(domain == linux.AF.INET or domain == linux.AF.INET6);
        assert(protocol == linux.IPPROTO.TCP or protocol == linux.IPPROTO.UDP or protocol == 0);
        assert(socket_type == linux.SOCK.STREAM or socket_type == linux.SOCK.DGRAM);

        operation.* = .{
            .create_socket = .{
                .domain = domain,
                .socket_type = socket_type,
                .protocol = protocol,
            },
        };
        const socket_flags = 0;
        const user_data: u64 = @intFromPtr(operation);
        _ = self.io_ring.socket(user_data, domain, socket_type, protocol, socket_flags) catch {
            warn_submission_queue_full(.create_socket);
            _ = self.submit_all_no_wait() catch unreachable;
            _ = self.io_ring.socket(user_data, domain, socket_type, protocol, socket_flags) catch unreachable;
        };
    }

    /// Used for replying during the command negotiation phase.
    pub fn enqueue_connection_reply_for_termination(self: *Socks5Proxy, connection: *Connection, reply: Reply) void {
        assert(reply != .success);
        assert(connection.kind == .client_tcp);
        assert(connection.state == .command_negotiation);
        defer assert(connection.state != .command_negotiation);

        const reply_index: usize = @intFromEnum(reply);
        assert(reply_index < failure_replies.len);
        const reply_bytes: []const u8 = &failure_replies[reply_index];

        connection.state = .{ .terminating_with_reply = reply };
        switch (connection.negotiated_auth_method) {
            // TODO(asap): TLS wrap the `reply_bytes` and store them in connection.buffer_ptr.
            .tls => unreachable,

            .none, .credentials => {
                const send_flags = 0;
                const no_timeout = null;
                self.enqueue_socket_send(
                    &connection.inflight_operation,
                    connection.socket,
                    reply_bytes,
                    send_flags,
                    no_timeout,
                );
            },
            else => unreachable,
        }
    }

    pub fn enqueue_connection_close(self: *Socks5Proxy, connection: *Connection) void {
        // TODO: connection.state == .terminated
        assert(connection.state == .terminating or connection.state == .terminating_with_reply);
        self.enqueue_close_fd(&connection.inflight_operation, connection.socket);
    }

    // Enqueues a receive using the buffer_ptr. It doesn't take into account the current state.
    // So avoid using it if you're in the middle of a negotiation phase like during auth negotiation
    // where you need to read into the middle of the buffer after having received some previous bytes.
    pub fn enqueue_connection_recv(
        self: *Socks5Proxy,
        connection: *Connection,
        timeout: ?struct { flags: u32, ts: linux.kernel_timespec },
    ) void {
        assert(connection.state != .terminating and connection.state != .terminating_with_reply);

        if (connection.kind == .client_tcp) {
            // As described in the doc for the function, we're only allowed to call this function
            // for a tcp client in the first read during a negotiation phase.
            switch (connection.state) {
                .command_negotiation => assert(connection.state.command_negotiation == 0),
                .auth_method_negotiation => assert(connection.state.auth_method_negotiation == 0),
                else => {},
            }
        }

        const recv_flags = 0;
        self.enqueue_socket_recv(
            &connection.inflight_operation,
            connection.socket,
            connection.buffer_ptr,
            recv_flags,
            if (timeout) |value| .{
                .ts = value.ts,
                .flags = value.flags,
            } else null,
        );
    }

    pub fn enqueue_socket_send(
        self: *Socks5Proxy,
        operation: *Operation,
        socket: linux.fd_t,
        buffer: []const u8,
        flags: u32,
        timeout: ?struct { flags: u32, ts: linux.kernel_timespec },
    ) void {
        assert(socket > 2);
        assert(buffer.len > 0);
        if (timeout) |value| {
            assert(value.ts.sec > 0 or value.ts.nsec > 0);
        }

        operation.* = .{
            .send = .{
                .socket = socket,
                .buffer = buffer,
                .flags = flags | linux.MSG.NOSIGNAL,
                .timeout = if (timeout) |value| .{
                    .ts = value.ts,
                    .flags = value.flags,
                } else null,
            },
        };

        const user_data: u64 = @intFromPtr(operation);
        if (timeout != null) {
            if (self.sq_space_left() < 2)
                _ = self.submit_all_no_wait() catch unreachable;

            var send_sqe = self.io_ring.send(
                user_data,
                operation.send.socket,
                operation.send.buffer,
                operation.send.flags,
            ) catch unreachable;
            send_sqe.flags = linux.IOSQE_IO_LINK;

            var link_timeout_sqe = self.io_ring.link_timeout(
                user_data,
                &operation.send.timeout.?.ts,
                operation.send.timeout.?.flags,
            ) catch unreachable;
            link_timeout_sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
        } else {
            _ = self.io_ring.send(
                user_data,
                operation.send.socket,
                operation.send.buffer,
                operation.send.flags,
            ) catch {
                warn_submission_queue_full(.send);
                _ = self.submit_all_no_wait() catch unreachable;
                _ = self.io_ring.send(
                    user_data,
                    operation.send.socket,
                    operation.send.buffer,
                    operation.send.flags,
                ) catch unreachable;
            };
        }
    }

    pub fn enqueue_socket_recv(
        self: *Socks5Proxy,
        operation: *Operation,
        socket: linux.fd_t,
        buffer: []u8,
        flags: u32,
        timeout: ?struct { flags: u32, ts: linux.kernel_timespec },
    ) void {
        assert(socket > 2);
        assert(buffer.len > 0);
        if (timeout) |value| {
            assert(value.ts.sec > 0 or value.ts.nsec > 0);
        }
        operation.* = .{
            .recv = .{
                .socket = socket,
                .buffer = buffer,
                .flags = flags,
                .timeout = if (timeout) |value| .{
                    .ts = value.ts,
                    .flags = value.flags,
                } else null,
            },
        };

        const user_data: u64 = @intFromPtr(operation);
        if (timeout != null) {
            if (self.sq_space_left() < 2)
                _ = self.submit_all_no_wait() catch unreachable;

            var recv_sqe = self.io_ring.recv(user_data, socket, .{ .buffer = buffer }, flags) catch unreachable;
            recv_sqe.flags |= linux.IOSQE_IO_LINK;

            var link_timeout_sqe = self.io_ring.link_timeout(
                user_data,
                &operation.recv.timeout.?.ts,
                operation.recv.timeout.?.flags,
            ) catch unreachable;
            link_timeout_sqe.flags |= linux.IOSQE_CQE_SKIP_SUCCESS;
        } else {
            _ = self.io_ring.recv(user_data, socket, .{ .buffer = buffer }, flags) catch {
                warn_submission_queue_full(.recv);
                _ = self.submit_all_no_wait() catch unreachable;
                _ = self.io_ring.recv(user_data, socket, .{ .buffer = buffer }, flags) catch unreachable;
            };
        }
    }

    pub fn enqueue_close_fd(self: *Socks5Proxy, operation: *Operation, fd: linux.fd_t) void {
        assert(fd >= 0);
        operation.* = .{
            .close = .{ .fd = fd },
        };
        const user_data: u64 = @intFromPtr(operation);
        var close_sqe = self.io_ring.close(user_data, fd) catch close_sqe: {
            warn_submission_queue_full(.close);
            _ = self.submit_all_no_wait() catch unreachable;
            break :close_sqe self.io_ring.close(user_data, fd) catch unreachable;
        };
        close_sqe.flags |= linux.IOSQE_ASYNC;
    }

    pub fn enqueue_read_signalfd(self: *Socks5Proxy) void {
        var operation: *Operation = &self.read_signalfd_operation;
        assert(operation.read_signalfd.fd > 2);

        const offset = 0;
        const user_data: u64 = @intFromPtr(operation);
        _ = self.io_ring.read(
            user_data,
            operation.read_signalfd.fd,
            .{ .buffer = std.mem.asBytes(&operation.read_signalfd.siginfo) },
            offset,
        ) catch {
            warn_submission_queue_full(.read_signalfd);
            _ = self.submit_all_no_wait() catch unreachable;
            _ = self.io_ring.read(
                user_data,
                operation.read_signalfd.fd,
                .{ .buffer = std.mem.asBytes(&operation.read_signalfd.siginfo) },
                offset,
            ) catch unreachable;
        };
    }

    pub fn enqueue_accept_clients(self: *Socks5Proxy) void {
        // NOTE: We need to write to the operation because the field gets repurposed
        // for closing sockets when the server is at capacity. Unlike enqueue_read_signalfd above
        // which doesn't change its internal Operation state.
        assert(self.server_socket > 2);
        self.accept_operation = .{
            .accept = .{
                .socket = self.server_socket,
                .address = undefined, // This will contain the address of the client on successfull accept(2).
                .address_size = switch (self.config.ip_address) {
                    .ip4 => @sizeOf(linux.sockaddr.in),
                    .ip6 => @sizeOf(linux.sockaddr.in6),
                },
            },
        };
        const user_data: u64 = @intFromPtr(&self.accept_operation);
        _ = self.io_ring.accept(
            user_data,
            self.accept_operation.accept.socket,
            &self.accept_operation.accept.address.any,
            &self.accept_operation.accept.address_size,
            linux.SOCK.CLOEXEC,
        ) catch {
            warn_submission_queue_full(.accept);
            _ = self.submit_all_no_wait() catch unreachable;
            _ = self.io_ring.accept(
                user_data,
                self.accept_operation.accept.socket,
                &self.accept_operation.accept.address.any,
                &self.accept_operation.accept.address_size,
                linux.SOCK.CLOEXEC,
            ) catch unreachable;
        };
    }

    pub fn next_session_id(self: *Socks5Proxy) SessionId {
        const next_id = self.session_id;
        self.session_id += 1;
        return next_id;
    }

    /// Modified version of tigerbeetle's submit_and_wait_timeout (io/linux.zig).
    /// Returns the number of submitted sqe entries on success. The timeout error is never returned.
    ///
    /// The timeout error is ignored because we're driving the ring at a fixed rate (~10ms).
    ///
    /// min_complete == 0 and timeout_nsec  > 0 => unreachable
    /// min_complete == 0 and timeout_nsec == 0 => submit without waiting
    /// min_complete >  0 and timeout_nsec == 0 => wait indefinitely for min_complete cqes to be available
    /// min_complete >  0 and timeout_nsec  > 0 => submit and wait for timeout or min_complete entries to be available
    pub fn submit_and_wait_timeout(self: *Socks5Proxy, min_complete: u32, timeout_nsec: u63) !u32 {
        assert(self.io_ring.fd > 2);

        var flags: u32 = 0;
        assert(self.io_ring.sq_ring_needs_enter(&flags)); // ensure sqpoll is disabled
        assert(flags == 0);

        if (timeout_nsec > 0)
            assert(min_complete > 0);

        const sqes_to_submit: u32 = self.io_ring.flush_sq();
        if (min_complete > 0) {
            flags |= linux.IORING_ENTER_GETEVENTS;
        }
        flags |= linux.IORING_ENTER_EXT_ARG;

        var timespec: linux.kernel_timespec = .{
            .sec = timeout_nsec / std.time.ns_per_s,
            .nsec = timeout_nsec % std.time.ns_per_s,
        };
        var arg: linux.io_uring_getevents_arg = .{
            .sigmask = 0,
            .sigmask_sz = linux.NSIG / 8,
            .pad = 0,
            .ts = 0,
        };
        if (timeout_nsec > 0) {
            arg.ts = @intFromPtr(&timespec);
        }
        _ = self.enter_with_extended_arg(sqes_to_submit, min_complete, flags, arg) catch |err| switch (err) {
            // This error concerns the CQEs when min_complete > 0, the SQEs were submitted to the kernel.
            error.TIME => {},

            // Only happens on ancient kernels according to Jens.
            // TODO: Dig into different kernel versions to see which ones this can happen on.
            error.BUSY => unreachable,

            // TODO: Are there errors which get reported but the SQEs were still submitted to the kernel?
            else => return err,
        };
        self.stats.total_sqes_submitted += sqes_to_submit;

        assert(self.sq_space_left() >= 2);
        return sqes_to_submit;
    }

    pub fn enter_with_extended_arg(self: *Socks5Proxy, to_submit: u32, min_complete: u32, flags: u32, arg: linux.io_uring_getevents_arg) OsError!u32 {
        assert(self.io_ring.fd > 2);
        assert((self.io_ring.features & linux.IORING_FEAT_EXT_ARG) != 0);

        assert((flags & linux.IORING_ENTER_EXT_ARG) != 0);
        if (min_complete > 0)
            assert((flags & linux.IORING_ENTER_GETEVENTS) != 0);

        if (arg.ts > 0)
            assert(min_complete > 0);

        const submitted_entries_count = linux.syscall6(
            .io_uring_enter,
            @intCast(self.io_ring.fd),
            to_submit,
            min_complete,
            flags,
            @intFromPtr(&arg),
            @sizeOf(linux.io_uring_getevents_arg),
        );
        const errno = linux.errno(submitted_entries_count);
        if (errno != .SUCCESS)
            return errno_as_error(errno);

        assert(submitted_entries_count <= std.math.maxInt(u32));
        const submitted_entries_count_u32: u32 = @intCast(submitted_entries_count);

        assert(submitted_entries_count_u32 == to_submit); // IORING_SETUP_SUBMIT_ALL
        return submitted_entries_count_u32;
    }

    pub fn submit_all_no_wait(self: *Socks5Proxy) !u32 {
        return self.submit_and_wait_timeout(0, 0);
    }

    pub fn sq_space_left(self: *Socks5Proxy) u32 {
        const used_sqes_count: u32 = self.io_ring.sq_ready();
        assert(used_sqes_count <= self.io_ring.sq.sqes.len);
        assert(self.io_ring.sq.sqes.len <= std.math.maxInt(u16));
        return @as(u32, @intCast(self.io_ring.sq.sqes.len)) - used_sqes_count;
    }

    // TODO: Maybe track how many of these were generated ?
    pub fn warn_submission_queue_full(operation_name: @EnumLiteral()) void {
        std.log.warn("{any}: submission queue is full. consider readjusting the ring size.", .{operation_name});
    }

    pub fn shutdown_deinit(self: *Socks5Proxy) void {
        self.io_ring.deinit();
    }

    pub fn deinit(self: *Socks5Proxy, allocator: std.mem.Allocator) void {
        _ = linux.close(self.read_signalfd_operation.read_signalfd.fd);
        _ = linux.close(self.server_socket);
        self.io_ring.deinit();
        self.buffer_pool.deinit(allocator);
        self.pending_clients.deinit(allocator);
        self.active_sessions.deinit(allocator);
        self.* = undefined;
    }
};

pub fn main(init: std.process.Init) !void {
    _ = &init.io;
    const allocator = std.heap.page_allocator;
    const address = "127.0.0.1";
    const bind_ip = try IP_Address.parse(address, constants.socks_port);
    const proxy_config = ProxyConfig{
        .io_ring_size = 256,
        .max_clients_count = 8,
        .max_udp_destinations = 32,
        .listen_backlog = 64,
        .defer_accept_timeout_sec = 10,
        .ip_address = bind_ip,

        .forbidden_dst_ports = &.{},
        .forbidden_dst_ipv4_addresses = &.{},
        .forbidden_dst_ipv6_addresses = &.{},
        .forbidden_dst_domain_names = &.{},
    };
    var socks_proxy = try Socks5Proxy.init(proxy_config, allocator);
    defer socks_proxy.deinit(allocator);

    std.log.info("started proxy on: {s}:{d}", .{ address, constants.socks_port });
    try socks_proxy.main_loop();
}
