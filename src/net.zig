const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const assert = std.debug.assert;

const IO = std.Io;
const IP_Address = IO.net.IpAddress;
const PosixAddress = IO.Threaded.PosixAddress;
const address_to_posix = IO.Threaded.addressToPosix;

const errno_as_error = @import("utils.zig").errno_as_error;
const OsError = @import("utils.zig").OsError;

pub fn setup_server_socket(address: IP_Address, listen_backlog: u32, defer_accept_timeout_sec: ?c_int) OsError!linux.fd_t {
    // TODO: use multipath TCP ?
    // const address: IP_Address = try .parse(ip_address, port);
    const socket_fd_result = switch (address) {
        .ip4 => linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0),
        .ip6 => linux.socket(linux.AF.INET6, linux.SOCK.STREAM, 0),
    };
    if (linux.errno(socket_fd_result) != .SUCCESS) {
        return errno_as_error(linux.errno(socket_fd_result));
    }
    const server_socket: linux.fd_t = @intCast(socket_fd_result);
    errdefer _ = linux.close(server_socket);
    assert(server_socket > 2);

    try posix.setsockopt(server_socket, linux.SOL.SOCKET, linux.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));

    if (defer_accept_timeout_sec) |timeout_sec| {
        assert(timeout_sec >= 0);
        try posix.setsockopt(server_socket, linux.IPPROTO.TCP, linux.TCP.DEFER_ACCEPT, &std.mem.toBytes(timeout_sec));
    }

    var posix_address: PosixAddress = undefined;
    const address_len = address_to_posix(&address, &posix_address);

    const bind_result = linux.bind(server_socket, &posix_address.any, address_len);
    if (linux.errno(bind_result) != .SUCCESS) {
        return errno_as_error(linux.errno(bind_result));
    }
    const listen_result = linux.listen(server_socket, listen_backlog);
    if (linux.errno(listen_result) != .SUCCESS) {
        return errno_as_error(linux.errno(listen_result));
    }
    return server_socket;
}

/// Takes a cqe.res, returns the corresponding errno as an error.
pub fn io_uring_error(res: i32) OsError {
    assert(res < 0);
    const errno: i32 = -res;
    const errno_enum: linux.E = @enumFromInt(errno);
    return errno_as_error(errno_enum);
}

pub fn get_address_length(ip_address: *const IP_Address) linux.socketlen_t {
    return switch (ip_address.*) {
        .ipv4 => @sizeOf(linux.sockaddr.in),
        .ipv6 => @sizeOf(linux.sockaddr.in6),
        else => unreachable,
    };
}

pub fn get_peer_name(socket: linux.fd_t, comptime T: enum { ipv4, ipv6 }) if (T == .ipv4) posix.sockaddr.in else posix.sockaddr.in6 {
    assert(socket > 2);
    var address = switch (T) {
        .ipv4 => std.mem.zeroInit(posix.sockaddr.in, .{}),
        .ipv6 => std.mem.zeroInit(posix.sockaddr.in6, .{}),
    };
    var addrlen: u32 = switch (T) {
        .ipv4 => @sizeOf(posix.sockaddr.in),
        .ipv6 => @sizeOf(posix.sockaddr.in6),
    };
    posix.getpeername(
        socket,
        @ptrCast(@alignCast(&address)), // NOTE: alignOf(sockaddr.in) > alignOf(sockaddr), thus: &sockaddr.in ≡ 0 [alignOf(sockaddr)]
        &addrlen,
    ) catch |err| {
        std.debug.panic("get_peer_name({d}, {any}): invalid error: {any}", .{ socket, T, err });
    };

    assert(addrlen == @sizeOf(@TypeOf(address)));
    return address;
}

pub fn is_private_ipv4_address(ip: u32) bool {
    const address: [4]u8 = std.mem.toBytes(ip);
    return (address[0] == 10) or
        (address[0] == 172 and address[1] & 0xf0 == 16) or
        (address[0] == 192 and address[1] == 168);
}

pub fn is_loopback_ipv4_address(ip: u32) bool {
    const address: [4]u8 = std.mem.toBytes(ip);
    return address[0] == 127;
}

pub fn get_socket_type(socket: linux.fd_t) OsError!u32 {
    assert(socket > 2);
    var socket_type: c_int = 0;
    var option_len: linux.socklen_t = @sizeOf(c_int);
    const get_option_result = linux.getsockopt(socket, linux.SOL.SOCKET, linux.SO.TYPE, @ptrCast(&socket_type), &option_len);
    if (linux.errno(get_option_result) != .SUCCESS)
        return errno_as_error(linux.errno(get_option_result));

    assert(socket_type >= 0 and socket_type <= std.math.maxInt(u32));
    return @intCast(socket_type);
}

pub fn ip_address_from_posix_address(posix_address: *const PosixAddress) u128 {
    return switch (posix_address.any.family) {
        linux.AF.INET => @as(u128, posix_address.in.addr),
        linux.AF.INET6 => std.mem.readInt(u128, &posix_address.in6.addr, .big), // TODO: test the endianess.
        else => unreachable,
    };
}

pub fn port_from_posix_address(posix_address: *const PosixAddress) u16 {
    const port: u16 = switch (posix_address.any.family) {
        linux.AF.INET => posix_address.in.port,
        linux.AF.INET6 => posix_address.in6.port,
        else => unreachable,
    };
    assert(port != 0); // Actually a valid port number that we don't support in the proxy.
    return port;
}

pub fn address_size_from_posix_address(posix_address: *const PosixAddress) u32 {
    return switch (posix_address.any.family) {
        linux.AF.INET => @sizeOf(linux.sockaddr.in),
        linux.AF.INET6 => @sizeOf(linux.sockaddr.in6),
        else => unreachable,
    };
}
