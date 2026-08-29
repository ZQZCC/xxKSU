use crate::{ksucalls, utils};
use anyhow::{Context, Result, bail};
use log::{info, warn};
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

const SOCKET_NAME: &[u8] = b"ksu_fdroot_v1";

#[repr(C)]
struct FdControl {
    header: libc::cmsghdr,
    fd: libc::c_int,
    padding: libc::c_int,
}

fn new_owned_fd(fd: libc::c_int) -> io::Result<OwnedFd> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn bind_listener() -> io::Result<OwnedFd> {
    let listener = new_owned_fd(unsafe {
        libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0)
    })?;

    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (destination, source) in address.sun_path[1..].iter_mut().zip(SOCKET_NAME) {
        *destination = *source as libc::c_char;
    }

    let address_len = (size_of::<libc::sa_family_t>() + 1 + SOCKET_NAME.len())
        .try_into()
        .expect("fd-root socket address fits socklen_t");
    let result = unsafe {
        libc::bind(
            listener.as_raw_fd(),
            (&raw const address).cast::<libc::sockaddr>(),
            address_len,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::listen(listener.as_raw_fd(), 16) } < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(listener)
}

fn accept_client(listener: RawFd) -> io::Result<OwnedFd> {
    new_owned_fd(unsafe {
        libc::accept4(
            listener,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    })
}

fn peer_credentials(socket: RawFd) -> io::Result<libc::ucred> {
    let mut credentials: libc::ucred = unsafe { zeroed() };
    let mut length = size_of::<libc::ucred>()
        .try_into()
        .expect("ucred size fits socklen_t");
    let result = unsafe {
        libc::getsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &raw mut length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<libc::ucred>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected SO_PEERCRED size",
        ));
    }

    Ok(credentials)
}

fn open_pidfd(pid: libc::pid_t) -> io::Result<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    let fd = libc::c_int::try_from(fd).unwrap_or(-1);
    new_owned_fd(fd)
}

fn send_capfd(socket: RawFd, capfd: RawFd) -> io::Result<()> {
    let mut payload = 0_u8;
    let mut iovec = libc::iovec {
        iov_base: (&raw mut payload).cast(),
        iov_len: 1,
    };
    let mut control = FdControl {
        header: libc::cmsghdr {
            cmsg_len: size_of::<libc::cmsghdr>() + size_of::<libc::c_int>(),
            cmsg_level: libc::SOL_SOCKET,
            cmsg_type: libc::SCM_RIGHTS,
        },
        fd: capfd,
        padding: 0,
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &raw mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = (&raw mut control).cast();
    message.msg_controllen = size_of::<FdControl>();

    let sent = unsafe { libc::sendmsg(socket, &raw const message, libc::MSG_NOSIGNAL) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent != 1 {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "fd-root broker sent an incomplete reply",
        ));
    }

    Ok(())
}

fn handle_client(client: RawFd) -> Result<()> {
    let credentials = peer_credentials(client).context("SO_PEERCRED failed")?;
    if credentials.pid <= 1 || credentials.uid == 0 {
        bail!(
            "refusing privileged fd-root peer pid={} uid={} gid={}",
            credentials.pid,
            credentials.uid,
            credentials.gid
        );
    }

    let pidfd = open_pidfd(credentials.pid)
        .with_context(|| format!("pidfd_open failed for pid {}", credentials.pid))?;
    let capfd = new_owned_fd(
        ksucalls::create_root_capfd(pidfd.as_raw_fd())
            .with_context(|| format!("CapFD denied for uid {}", credentials.uid))?,
    )?;
    send_capfd(client, capfd.as_raw_fd()).context("SCM_RIGHTS send failed")
}

pub fn ensure_server_running() -> Result<()> {
    if !ksucalls::supports_capfd_root() {
        return Ok(());
    }

    if utils::create_daemon(true)? {
        let mut command = Command::new("/proc/self/exe");
        command
            .arg("fd-root-server")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .current_dir("/");

        let error = command.exec();
        log::error!("failed to exec fd-root broker: {error:#}");
        unsafe {
            libc::_exit(1);
        }
    }

    Ok(())
}

pub fn run_server() -> Result<()> {
    if !ksucalls::supports_capfd_root() {
        bail!("kernel does not support root CapFDs");
    }

    let listener = bind_listener().context("failed to bind fd-root socket")?;
    info!("fd-root broker started");
    loop {
        let client = match accept_client(listener.as_raw_fd()) {
            Ok(client) => client,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("fd-root accept failed"),
        };
        if let Err(error) = handle_client(client.as_raw_fd()) {
            warn!("fd-root request failed: {error:#}");
        }
    }
}
