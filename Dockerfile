FROM debian:latest as builder
LABEL previous-stage=builder

# prepare builder
RUN apt update && apt install -y build-essential curl
# do make
RUN mkdir -p /build/

COPY . /build/

RUN /build/build.sh

FROM busybox:latest

COPY --from=builder /build/install /build/install

CMD ["/bin/bash"]