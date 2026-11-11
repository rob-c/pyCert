# Test image for one Linux distribution:
#
#   docker build -f docker/Dockerfile --build-arg BASE=ubuntu:24.04 -t pycert-test:ubuntu24 .
#
# tools/docker_matrix.sh builds and runs every supported distribution.
ARG BASE=ubuntu:24.04
FROM ${BASE}

COPY docker/install-deps.sh /tmp/install-deps.sh
RUN sh /tmp/install-deps.sh && rm /tmp/install-deps.sh

# The source last, so a code change does not reinstall the dependencies.
COPY . /work
RUN /venv/bin/pip install --quiet --no-deps -e /work
# Tests run as an ordinary user (some images already have one with uid 1000).
RUN (getent passwd 1000 >/dev/null || useradd --create-home --uid 1000 tester) && chown -R 1000:1000 /work

USER 1000
WORKDIR /work
ENV PATH=/venv/bin:$PATH \
    QT_QPA_PLATFORM=offscreen \
    PYTHONDONTWRITEBYTECODE=1
CMD ["pytest", "-n", "8", "-p", "no:cacheprovider", "-rfE"]
