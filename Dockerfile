FROM debian:latest as builder
LABEL previous-stage=builder

# prepare builder
RUN apt update -qq && apt install -qq -y build-essential curl gpg
# do make
RUN mkdir -p /build/

COPY . /build/

RUN /build/build.sh

FROM busybox:latest

COPY --from=builder /build/install /build/install

CMD ["/bin/bash"]