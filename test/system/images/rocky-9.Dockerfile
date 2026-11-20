# Rocky Linux 9 with systemd as PID 1, for system tests of the agent packages.
FROM rockylinux/rockylinux:9
RUN dnf -y install systemd dbus procps-ng sudo && dnf clean all \
    && systemctl mask systemd-logind.service getty.target console-getty.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
