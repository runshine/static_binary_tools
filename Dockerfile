FROM debian:latest as builder
LABEL previous-stage=builder

# prepare builder
RUN apt update -qq && apt install -qq -y build-essential curl gpg
# do make
RUN mkdir -p /build/

RUN mkdir -p /common/

RUN curl -o /common/prepare_dir.sh https://raw.githubusercontent.com/runshine/static_binary_tools/refs/heads/main/build/common/prepare_dir.sh && chmod +x /common/prepare_dir.sh

COPY . /build/

RUN /build/build.sh

FROM busybox:latest

COPY --from=builder /build/install /build/install

CMD ["/bin/bash"]