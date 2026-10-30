const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const assert = std.debug.assert;
const panic = std.debug.panic;

pub fn clock_gettime(clock_type: linux.clockid_t) !linux.timespec {
    var timespec: linux.timespec = .{ .sec = 0, .nsec = 0 };
    const result: linux.E = linux.errno(linux.clock_gettime(clock_type, &timespec));
    if (result != .SUCCESS) {
        return errno_as_error(result);
    }
    if (timespec.nsec < 0 or timespec.nsec > 999_999_999 or timespec.sec < 0) {
        panic("kernel/hardware bug resulted in invalid timespec value: {any}\n", .{timespec});
    }
    return timespec;
}

/// The upper bound memory required to run the proxy.
/// To do this, we need to measure this against the UDP associate
/// command which is what consumes the most amount of memory.
pub fn total_buffers_count(
    max_clients_count: u16,
    max_udp_destinations: u8,
) usize {
    assert(max_clients_count > 0);
    assert(max_udp_destinations > 0);
    var total: usize = 0;
    total += 1; // client tcp connection to the proxy.
    total += 1; // client udp connection to the proxy.
    total += max_udp_destinations; // proxy udp connections to destinations.
    total *= max_clients_count;
    return total;
}

pub fn setup_signalfd(signals: []const linux.SIG) !linux.fd_t {
    var signal_set: linux.sigset_t = linux.sigemptyset();
    for (signals) |sig| {
        linux.sigaddset(&signal_set, sig);
    }
    posix.sigprocmask(linux.SIG.SETMASK, &signal_set, null);
    return posix.signalfd(-1, &signal_set, 0);
}

// Taken from tigerbeetle.
pub const Time = struct {
    monotonic_guard: u64 = 0,

    /// Returns the amount of nanoseconds that have passed since the machine booted including time spent in a suspended state.
    pub fn monotonic_clock(time: *Time) u64 {
        const raw_timespec = clock_gettime(.BOOTTIME) catch |err| {
            panic("failed querying BOOTTIME clock: {any}", .{err});
        };
        const timespec: u64 = @as(u64, @intCast(raw_timespec.sec)) * std.time.ns_per_s + @as(u64, @intCast(raw_timespec.nsec));
        if (timespec < time.monotonic_guard) {
            panic("monotonic clock went backward: {any} < {any}", .{ timespec, time.monotonic_guard });
        }
        return timespec;
    }

    pub fn get_realtime(_: *Time) i64 {
        const timespec = clock_gettime(.REALTIME) catch |err| {
            panic("failed querying REALTIME clock: {any}", .{err});
        };
        return @as(i64, @intCast(timespec.sec)) * std.time.ns_per_s + timespec.nsec;
    }
};

pub const OsError = error{
    PERM,
    NOENT,
    SRCH,
    INTR,
    IO,
    NXIO,
    @"2BIG",
    NOEXEC,
    BADF,
    CHILD,
    AGAIN,
    NOMEM,
    ACCES,
    FAULT,
    NOTBLK,
    BUSY,
    EXIST,
    XDEV,
    NODEV,
    NOTDIR,
    ISDIR,
    INVAL,
    NFILE,
    MFILE,
    NOTTY,
    TXTBSY,
    FBIG,
    NOSPC,
    SPIPE,
    ROFS,
    MLINK,
    PIPE,
    DOM,
    RANGE,
    DEADLK,
    NAMETOOLONG,
    NOLCK,
    NOSYS,
    NOTEMPTY,
    LOOP,
    NOMSG,
    IDRM,
    CHRNG,
    L2NSYNC,
    L3HLT,
    L3RST,
    LNRNG,
    UNATCH,
    NOCSI,
    L2HLT,
    BADE,
    BADR,
    XFULL,
    NOANO,
    BADRQC,
    BADSLT,
    BFONT,
    NOSTR,
    NODATA,
    TIME,
    NOSR,
    NONET,
    NOPKG,
    REMOTE,
    NOLINK,
    ADV,
    SRMNT,
    COMM,
    PROTO,
    MULTIHOP,
    DOTDOT,
    BADMSG,
    OVERFLOW,
    NOTUNIQ,
    BADFD,
    REMCHG,
    LIBACC,
    LIBBAD,
    LIBSCN,
    LIBMAX,
    LIBEXEC,
    ILSEQ,
    RESTART,
    STRPIPE,
    USERS,
    NOTSOCK,
    DESTADDRREQ,
    MSGSIZE,
    PROTOTYPE,
    NOPROTOOPT,
    PROTONOSUPPORT,
    SOCKTNOSUPPORT,
    OPNOTSUPP,
    PFNOSUPPORT,
    AFNOSUPPORT,
    ADDRINUSE,
    ADDRNOTAVAIL,
    NETDOWN,
    NETUNREACH,
    NETRESET,
    CONNABORTED,
    CONNRESET,
    NOBUFS,
    ISCONN,
    NOTCONN,
    SHUTDOWN,
    TOOMANYREFS,
    TIMEDOUT,
    CONNREFUSED,
    HOSTDOWN,
    HOSTUNREACH,
    ALREADY,
    INPROGRESS,
    STALE,
    UCLEAN,
    NOTNAM,
    NAVAIL,
    ISNAM,
    REMOTEIO,
    DQUOT,
    NOMEDIUM,
    MEDIUMTYPE,
    CANCELED,
    NOKEY,
    KEYEXPIRED,
    KEYREVOKED,
    KEYREJECTED,
    OWNERDEAD,
    NOTRECOVERABLE,
    RFKILL,
    HWPOISON,
    NSRNODATA,
    NSRFORMERR,
    NSRSERVFAIL,
    NSRNOTFOUND,
    NSRNOTIMP,
    NSRREFUSED,
    NSRBADQUERY,
    NSRBADNAME,
    NSRBADFAMILY,
    NSRBADRESP,
    NSRCONNREFUSED,
    NSRTIMEOUT,
    NSROF,
    NSRFILE,
    NSRNOMEM,
    NSRDESTRUCTION,
    NSRQUERYDOMAINTOOLONG,
    NSRCNAMELOOP,
};

// Accepts any non success errno value and return the equivalent error.
pub fn errno_as_error(errno: linux.E) OsError {
    return switch (errno) {
        else => unreachable,
        .SUCCESS => unreachable,
        // Operation not permitted
        .PERM => error.PERM,
        // No such file or directory
        .NOENT => error.NOENT,
        // No such process
        .SRCH => error.SRCH,
        // Interrupted system call
        .INTR => error.INTR,
        // I/O error
        .IO => error.IO,
        // No such device or address
        .NXIO => error.NXIO,
        // Arg list too long
        .@"2BIG" => error.@"2BIG",
        // Exec format error
        .NOEXEC => error.NOEXEC,
        // Bad file number
        .BADF => error.BADF,
        // No child processes
        .CHILD => error.CHILD,
        // Try again. Also means: WOULDBLOCK: operation would block
        .AGAIN => error.AGAIN,
        // Out of memory
        .NOMEM => error.NOMEM,
        // Permission denied
        .ACCES => error.ACCES,
        // Bad address
        .FAULT => error.FAULT,
        // Block device required
        .NOTBLK => error.NOTBLK,
        // Device or resource busy
        .BUSY => error.BUSY,
        // File exists
        .EXIST => error.EXIST,
        // Cross-device link
        .XDEV => error.XDEV,
        // No such device
        .NODEV => error.NODEV,
        // Not a directory
        .NOTDIR => error.NOTDIR,
        // Is a directory
        .ISDIR => error.ISDIR,
        // Invalid argument
        .INVAL => error.INVAL,
        // File table overflow
        .NFILE => error.NFILE,
        // Too many open files
        .MFILE => error.MFILE,
        // Not a typewriter
        .NOTTY => error.NOTTY,
        // Text file busy
        .TXTBSY => error.TXTBSY,
        // File too large
        .FBIG => error.FBIG,
        // No space left on device
        .NOSPC => error.NOSPC,
        // Illegal seek
        .SPIPE => error.SPIPE,
        // Read-only file system
        .ROFS => error.ROFS,
        // Too many links
        .MLINK => error.MLINK,
        // Broken pipe
        .PIPE => error.PIPE,
        // Math argument out of domain of func
        .DOM => error.DOM,
        // Math result not representable
        .RANGE => error.RANGE,
        // Resource deadlock would occur
        .DEADLK => error.DEADLK,
        // File name too long
        .NAMETOOLONG => error.NAMETOOLONG,
        // No record locks available
        .NOLCK => error.NOLCK,
        // Function not implemented
        .NOSYS => error.NOSYS,
        // Directory not empty
        .NOTEMPTY => error.NOTEMPTY,
        // Too many symbolic links encountered
        .LOOP => error.LOOP,
        // No message of desired type
        .NOMSG => error.NOMSG,
        // Identifier removed
        .IDRM => error.IDRM,
        // Channel number out of range
        .CHRNG => error.CHRNG,
        // Level 2 not synchronized
        .L2NSYNC => error.L2NSYNC,
        // Level 3 halted
        .L3HLT => error.L3HLT,
        // Level 3 reset
        .L3RST => error.L3RST,
        // Link number out of range
        .LNRNG => error.LNRNG,
        // Protocol driver not attached
        .UNATCH => error.UNATCH,
        // No CSI structure available
        .NOCSI => error.NOCSI,
        // Level 2 halted
        .L2HLT => error.L2HLT,
        // Invalid exchange
        .BADE => error.BADE,
        // Invalid request descriptor
        .BADR => error.BADR,
        // Exchange full
        .XFULL => error.XFULL,
        // No anode
        .NOANO => error.NOANO,
        // Invalid request code
        .BADRQC => error.BADRQC,
        // Invalid slot
        .BADSLT => error.BADSLT,
        // Bad font file format
        .BFONT => error.BFONT,
        // Device not a stream
        .NOSTR => error.NOSTR,
        // No data available
        .NODATA => error.NODATA,
        // Timer expired
        .TIME => error.TIME,
        // Out of streams resources
        .NOSR => error.NOSR,
        // Machine is not on the network
        .NONET => error.NONET,
        // Package not installed
        .NOPKG => error.NOPKG,
        // Object is remote
        .REMOTE => error.REMOTE,
        // Link has been severed
        .NOLINK => error.NOLINK,
        // Advertise error
        .ADV => error.ADV,
        // Srmount error
        .SRMNT => error.SRMNT,
        // Communication error on send
        .COMM => error.COMM,
        // Protocol error
        .PROTO => error.PROTO,
        // Multihop attempted
        .MULTIHOP => error.MULTIHOP,
        // RFS specific error
        .DOTDOT => error.DOTDOT,
        // Not a data message
        .BADMSG => error.BADMSG,
        // Value too large for defined data type
        .OVERFLOW => error.OVERFLOW,
        // Name not unique on network
        .NOTUNIQ => error.NOTUNIQ,
        // File descriptor in bad state
        .BADFD => error.BADFD,
        // Remote address changed
        .REMCHG => error.REMCHG,
        // Can not access a needed shared library
        .LIBACC => error.LIBACC,
        // Accessing a corrupted shared library
        .LIBBAD => error.LIBBAD,
        // .lib section in a.out corrupted
        .LIBSCN => error.LIBSCN,
        // Attempting to link in too many shared libraries
        .LIBMAX => error.LIBMAX,
        // Cannot exec a shared library directly
        .LIBEXEC => error.LIBEXEC,
        // Illegal byte sequence
        .ILSEQ => error.ILSEQ,
        // Interrupted system call should be restarted
        .RESTART => error.RESTART,
        // Streams pipe error
        .STRPIPE => error.STRPIPE,
        // Too many users
        .USERS => error.USERS,
        // Socket operation on non-socket
        .NOTSOCK => error.NOTSOCK,
        // Destination address required
        .DESTADDRREQ => error.DESTADDRREQ,
        // Message too long
        .MSGSIZE => error.MSGSIZE,
        // Protocol wrong type for socket
        .PROTOTYPE => error.PROTOTYPE,
        // Protocol not available
        .NOPROTOOPT => error.NOPROTOOPT,
        // Protocol not supported
        .PROTONOSUPPORT => error.PROTONOSUPPORT,
        // Socket type not supported
        .SOCKTNOSUPPORT => error.SOCKTNOSUPPORT,
        // Operation not supported on transport endpoint. This code also means `NOTSUP`.
        .OPNOTSUPP => error.OPNOTSUPP,
        // Protocol family not supported
        .PFNOSUPPORT => error.PFNOSUPPORT,
        // Address family not supported by protocol
        .AFNOSUPPORT => error.AFNOSUPPORT,
        // Address already in use
        .ADDRINUSE => error.ADDRINUSE,
        // Cannot assign requested address
        .ADDRNOTAVAIL => error.ADDRNOTAVAIL,
        // Network is down
        .NETDOWN => error.NETDOWN,
        // Network is unreachable
        .NETUNREACH => error.NETUNREACH,
        // Network dropped connection because of reset
        .NETRESET => error.NETRESET,
        // Software caused connection abort
        .CONNABORTED => error.CONNABORTED,
        // Connection reset by peer
        .CONNRESET => error.CONNRESET,
        // No buffer space available
        .NOBUFS => error.NOBUFS,
        // Transport endpoint is already connected
        .ISCONN => error.ISCONN,
        // Transport endpoint is not connected
        .NOTCONN => error.NOTCONN,
        // Cannot send after transport endpoint shutdown
        .SHUTDOWN => error.SHUTDOWN,
        // Too many references: cannot splice
        .TOOMANYREFS => error.TOOMANYREFS,
        // Connection timed out
        .TIMEDOUT => error.TIMEDOUT,
        // Connection refused
        .CONNREFUSED => error.CONNREFUSED,
        // Host is down
        .HOSTDOWN => error.HOSTDOWN,
        // No route to host
        .HOSTUNREACH => error.HOSTUNREACH,
        // Operation already in progress
        .ALREADY => error.ALREADY,
        // Operation now in progress
        .INPROGRESS => error.INPROGRESS,
        // Stale NFS file handle
        .STALE => error.STALE,
        // Structure needs cleaning
        .UCLEAN => error.UCLEAN,
        // Not a XENIX named type file
        .NOTNAM => error.NOTNAM,
        // No XENIX semaphores available
        .NAVAIL => error.NAVAIL,
        // Is a named type file
        .ISNAM => error.ISNAM,
        // Remote I/O error
        .REMOTEIO => error.REMOTEIO,
        // Quota exceeded
        .DQUOT => error.DQUOT,
        // No medium found
        .NOMEDIUM => error.NOMEDIUM,
        // Wrong medium type
        .MEDIUMTYPE => error.MEDIUMTYPE,
        // Operation canceled
        .CANCELED => error.CANCELED,
        // Required key not available
        .NOKEY => error.NOKEY,
        // Key has expired
        .KEYEXPIRED => error.KEYEXPIRED,
        // Key has been revoked
        .KEYREVOKED => error.KEYREVOKED,
        // Key was rejected by service
        .KEYREJECTED => error.KEYREJECTED,
        // for robust mutexes
        // Owner died
        .OWNERDEAD => error.OWNERDEAD,
        // State not recoverable
        .NOTRECOVERABLE => error.NOTRECOVERABLE,
        // Operation not possible due to RF-kill
        .RFKILL => error.RFKILL,
        // Memory page has hardware error
        .HWPOISON => error.HWPOISON,
        // nameserver query return codes. DNS server returned answer with no data
        .NSRNODATA => error.NSRNODATA,
        // DNS server claims query was misformatted
        .NSRFORMERR => error.NSRFORMERR,
        // DNS server returned general failure
        .NSRSERVFAIL => error.NSRSERVFAIL,
        // Domain name not found
        .NSRNOTFOUND => error.NSRNOTFOUND,
        // DNS server does not implement requested operation
        .NSRNOTIMP => error.NSRNOTIMP,
        // DNS server refused query
        .NSRREFUSED => error.NSRREFUSED,
        // Misformatted DNS query
        .NSRBADQUERY => error.NSRBADQUERY,
        // Misformatted domain name
        .NSRBADNAME => error.NSRBADNAME,
        // Unsupported address family
        .NSRBADFAMILY => error.NSRBADFAMILY,
        // Misformatted DNS reply
        .NSRBADRESP => error.NSRBADRESP,
        // Could not contact DNS servers
        .NSRCONNREFUSED => error.NSRCONNREFUSED,
        // Timeout while contacting DNS servers
        .NSRTIMEOUT => error.NSRTIMEOUT,
        // End of file
        .NSROF => error.NSROF,
        // Error reading file
        .NSRFILE => error.NSRFILE,
        // Out of memory
        .NSRNOMEM => error.NSRNOMEM,
        // Application terminated lookup
        .NSRDESTRUCTION => error.NSRDESTRUCTION,
        // Domain name is too long
        .NSRQUERYDOMAINTOOLONG => error.NSRQUERYDOMAINTOOLONG,
        // Domain name is too long
        .NSRCNAMELOOP => error.NSRCNAMELOOP,
    };
}
