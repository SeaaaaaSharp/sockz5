const std = @import("std");

pub const assert = std.debug.assert;

pub const socks_port: u16 = 1080;

pub const http_3_port: u16 = 443;

pub const wireguard_port: u16 = 51820;

pub const socks_version: u8 = 5;

pub const graceful_shutdown_duration_sec = 15;

pub const domain_name_max_len: u8 = 255;

pub const min_username_length: u8 = 6;

pub const min_password_length: u8 = 12;

/// RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(4) + DST.PORT(2) + DATA(0)
pub const minimum_client_udp_message_size: u8 = 2 + 1 + 1 + 4 + 2 + 0;

// Userspace buffer which we use to receive and send data.
// There are exactly total_buffers_count(max_clients_count, max_udp_destinations)
// of these available for the application to use.
pub const max_buffer_size: usize = 65_536; // 64 kib per client should be more than enough.

/// NOTE: Be aware that each connection to a target server requires an upfront `udp_message_max_size` buffer allocation.
pub const max_destination_connections_per_udp_association: u8 = 32;

/// Used to compute the auth method negotiation deadline after the client joins.
/// Deadline is computed relative to when the client connection was established.
pub const max_auth_negotiation_deadline_sec = 5;

/// Used to compute the sub-negotiation deadline after the server selected the credentials auth method.
/// Deadline is computed relative to when the client connection was established.
pub const max_credentials_method_sub_negotiation_deadline_sec = 10;

/// Used to compute the command negotiation deadline after the client joins.
/// Deadline is computed relative to when the client connection was established.
pub const max_command_negotiation_deadline_sec = 15;

/// Used to compute the deadline when connecting to the destination server after the client joins.
/// Deadline is computed relative to when the client connection was established.
pub const max_connect_deadline_sec = 25;

comptime {
    assert(max_auth_negotiation_deadline_sec < max_credentials_method_sub_negotiation_deadline_sec);
    assert(max_credentials_method_sub_negotiation_deadline_sec < max_command_negotiation_deadline_sec);
    assert(max_command_negotiation_deadline_sec < max_connect_deadline_sec);
    assert(min_password_length >= 12);
}
