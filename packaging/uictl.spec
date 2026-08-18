# RPM spec for uictl. Mirrors packaging/debian/ -- the upstream Makefile
# honours DESTDIR and the GNU *dir variables, so both packagings are
# thin.
Name:           uictl
Version:        0.3.0
Release:        1%{?dist}
Summary:        Typed-RPC broker for /dev/uinput

License:        MIT
URL:            https://github.com/stupakzm/uictl
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  python3
Recommends:     apparmor-utils

%description
uictld holds the /dev/uinput file descriptor and mediates every input
injection request over an AF_UNIX socket: rate limits, a static
destructive-key deny-list, a per-user keycode allowlist, an audit log,
and an optional confirmation prompt for flagged clients.

It exists because Linux file permissions are UID+GID+mode, so the kernel
cannot gate /dev/uinput per-binary. Installing this package does not
change that on its own -- the point is to remove input-group membership
from everything else and leave the broker as the sole holder of the
device.

%package        devel
Summary:        C client library for the uictl input broker
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description    devel
Headers, static and shared library for talking to uictld from C.

The library is a convenience, not the contract: %{_datadir}/uictl/WIRE.md
is the normative protocol specification and includes byte-exact
conformance vectors, so a client in any language can be written without
linking this.

%prep
%autosetup

%build
# %%set_build_flags supplies the distribution's hardening; the Makefile's
# `override CFLAGS +=` appends the project's on top rather than
# replacing them.
%make_build all lib

%install
%make_install prefix=%{_prefix} libdir=%{_libdir} libexecdir=%{_libexecdir}

%check
# The device suites need a real /dev/uinput and a session to inject
# into. A build host has neither, and a build that typed into a machine
# it does not own would be a remarkable thing to ship. Only the
# device-free ones run here.
python3 tests/test_wire9_vectors.py

%files
%license LICENSE
%doc README.md
%{_libexecdir}/uictld
%{_bindir}/uictl
%{_bindir}/uictl-confirm
%{_userunitdir}/uictld.socket
%{_userunitdir}/uictld.service
%dir %{_datadir}/uictl
%{_datadir}/uictl/proto.json
%{_datadir}/uictl/vectors.json
%{_datadir}/uictl/WIRE.md
%config(noreplace) %{_sysconfdir}/apparmor.d/usr.libexec.uictld

%files devel
%dir %{_includedir}/uictl
%{_includedir}/uictl/uictl.h
%{_libdir}/libuictl.a
%{_libdir}/libuictl.so
%{_libdir}/pkgconfig/uictl.pc

%post
# Two things this package deliberately does not do: add anyone to the
# input group, and enable a per-user socket unit. Both are the
# administrator's and the user's calls respectively.
cat <<'MSG'

uictl is installed. Next, per user:

    sudo usermod -aG input $USER          # log out and back in
    systemctl --user enable --now uictld.socket

Enable the SOCKET, not the service: it exists from login and the daemon
starts on the first client connection. And take input-group membership
away from anything else that has it -- that is the whole point.

MSG

%changelog
* Mon Aug 18 2026 stupakzm <zaharstupak657@gmail.com> - 0.3.0-1
- Initial packaging.
