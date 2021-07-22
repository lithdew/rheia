const std = @import("std");

const os = std.os;

pub fn handleReadError(result: isize) !bool {
    if (result < 0) {
        return switch (-result) {
            os.EBADF => unreachable,
            os.EFAULT => unreachable,
            os.EINVAL => unreachable,
            os.ENOTCONN => unreachable,
            os.ENOTSOCK => unreachable,
            os.EINTR => false,
            os.EAGAIN => error.WouldBlock,
            os.ENOMEM => error.SystemResources,
            os.ECONNREFUSED => error.ConnectionRefused,
            os.ECONNRESET => error.ConnectionResetByPeer,
            else => |err| os.unexpectedErrno(err),
        };
    }
    return true;
}

pub fn handleRecvError(result: isize) !bool {
    if (result < 0) {
        return switch (-result) {
            os.EBADF => unreachable,
            os.EFAULT => unreachable,
            os.EINVAL => unreachable,
            os.ENOTCONN => unreachable,
            os.ENOTSOCK => unreachable,
            os.EINTR => false,
            os.EAGAIN => error.WouldBlock,
            os.ENOMEM => error.SystemResources,
            os.ECONNREFUSED => error.ConnectionRefused,
            os.ECONNRESET => error.ConnectionResetByPeer,
            else => |err| os.unexpectedErrno(err),
        };
    }
    return true;
}

pub fn handleWriteError(result: isize) !bool {
    if (result < 0) {
        return switch (-result) {
            os.EINTR => false,
            os.EINVAL => unreachable,
            os.EFAULT => unreachable,
            os.EAGAIN => return error.WouldBlock,
            os.EBADF => return error.NotOpenForWriting,
            os.EDESTADDRREQ => unreachable,
            os.EDQUOT => return error.DiskQuota,
            os.EFBIG => return error.FileTooBig,
            os.EIO => return error.InputOutput,
            os.ENOSPC => return error.NoSpaceLeft,
            os.EPERM => return error.AccessDenied,
            os.EPIPE => return error.BrokenPipe,
            os.ECONNRESET => return error.ConnectionResetByPeer,
            else => |err| return os.unexpectedErrno(err),
        };
    }
    return true;
}

pub fn handleSendError(result: isize) !bool {
    if (result < 0) {
        return switch (-result) {
            os.EACCES => error.AccessDenied,
            os.EAGAIN => error.WouldBlock,
            os.EALREADY => error.FastOpenAlreadyInProgress,
            os.EBADF => unreachable,
            os.ECONNRESET => error.ConnectionResetByPeer,
            os.EDESTADDRREQ => unreachable,
            os.EFAULT => unreachable,
            os.EINTR => false,
            os.EINVAL => unreachable,
            os.EISCONN => unreachable,
            os.EMSGSIZE => error.MessageTooBig,
            os.ENOBUFS => error.SystemResources,
            os.ENOMEM => error.SystemResources,
            os.ENOTSOCK => unreachable,
            os.EOPNOTSUPP => unreachable,
            os.EPIPE => error.BrokenPipe,
            os.EAFNOSUPPORT => error.AddressFamilyNotSupported,
            os.ELOOP => error.SymLinkLoop,
            os.ENAMETOOLONG => error.NameTooLong,
            os.ENOENT => error.FileNotFound,
            os.ENOTDIR => error.NotDir,
            os.EHOSTUNREACH => error.NetworkUnreachable,
            os.ENETUNREACH => error.NetworkUnreachable,
            os.ENOTCONN => error.SocketNotConnected,
            os.ENETDOWN => error.NetworkSubsystemFailed,
            else => |err| os.unexpectedErrno(err),
        };
    }
    return true;
}

pub fn handleConnectError(result: isize) !bool {
    if (result < 0) {
        return switch (-result) {
            os.EACCES => error.PermissionDenied,
            os.EPERM => error.PermissionDenied,
            os.EADDRINUSE => error.AddressInUse,
            os.EADDRNOTAVAIL => error.AddressNotAvailable,
            os.EAFNOSUPPORT => error.AddressFamilyNotSupported,
            os.EAGAIN, os.EINPROGRESS => error.WouldBlock,
            os.EALREADY => error.ConnectionPending,
            os.EBADF => unreachable,
            os.ECONNREFUSED => error.ConnectionRefused,
            os.ECONNRESET => error.ConnectionResetByPeer,
            os.EFAULT => unreachable,
            os.EINTR => false,
            os.EISCONN => unreachable,
            os.ENETUNREACH => error.NetworkUnreachable,
            os.ENOTSOCK => unreachable,
            os.EPROTOTYPE => unreachable,
            os.ETIMEDOUT => error.ConnectionTimedOut,
            os.ENOENT => error.FileNotFound,
            else => |err| os.unexpectedErrno(err),
        };
    }
    return true;
}

pub fn handleAcceptError(result: isize) !bool {
    if (result < 0) {
        return switch (-result) {
            os.EINTR => false,
            os.EAGAIN => return error.WouldBlock,
            os.EBADF => unreachable,
            os.ECONNABORTED => return error.ConnectionAborted,
            os.EFAULT => unreachable,
            os.EINVAL => return error.SocketNotListening,
            os.ENOTSOCK => unreachable,
            os.EMFILE => return error.ProcessFdQuotaExceeded,
            os.ENFILE => return error.SystemFdQuotaExceeded,
            os.ENOBUFS => return error.SystemResources,
            os.ENOMEM => return error.SystemResources,
            os.EOPNOTSUPP => unreachable,
            os.EPROTO => return error.ProtocolFailure,
            os.EPERM => return error.BlockedByFirewall,
            else => |err| return os.unexpectedErrno(err),
        };
    }
    return true;
}
