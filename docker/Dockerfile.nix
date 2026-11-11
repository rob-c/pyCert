# Test image with Nix: Python, PySide6 and Qt from nixpkgs (see shell.nix).
#
#   docker build -f docker/Dockerfile.nix -t pycert-test:nix .
FROM nixos/nix:latest

# Nix's seccomp filter cannot load under emulated x86_64 (Docker on Apple silicon).
RUN printf 'filter-syscalls = false\nsandbox = false\n' >> /etc/nix/nix.conf
COPY docker/shell.nix /work/docker/shell.nix
# Realise the environment once, and record it so tests can run as a normal user.
RUN nix-shell /work/docker/shell.nix --run 'export -p | grep -v -E "^declare -x (USER|LOGNAME|HOME|PWD|OLDPWD|SHLVL|HOSTNAME|TERM|TMP|TMPDIR|TEMP|TEMPDIR|NIX_BUILD_TOP)=" > /etc/pycert-env.sh; python -c "import sys, PySide6, cryptography; print(sys.version.split()[0], \"PySide6\", PySide6.__version__, \"cryptography\", cryptography.__version__)"' \
    && echo 'tester:x:1000:1000::/tmp/home:/bin/sh' >> /etc/passwd \
    && echo 'tester:x:1000:' >> /etc/group

COPY . /work
RUN mkdir -p /tmp/home && chown -R 1000:1000 /work /tmp/home

USER 1000
WORKDIR /work
# nixos/nix sets USER=root; tests run as the ordinary user created above.
ENV HOME=/tmp/home USER=tester LOGNAME=tester QT_QPA_PLATFORM=offscreen PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["bash", "-c", ". /etc/pycert-env.sh && export QT_QPA_PLATFORM=${QT_QPA_PLATFORM} HOME=/tmp/home && exec \"$@\"", "--"]
CMD ["python", "-m", "pytest", "-n", "8", "-p", "no:cacheprovider", "-rfE"]
