FROM debian:latest as builder
LABEL previous-stage=builder

# prepare builder
RUN apt update -qq && apt install -qq -y build-essential curl gpg python3
# do make
RUN mkdir -p /build/

RUN mkdir -p /common/

RUN curl -o /common/prepare_dir.sh https://raw.githubusercontent.com/runshine/static_binary_tools/refs/heads/main/build/common/prepare_dir.sh && chmod +x /common/prepare_dir.sh
RUN curl -o /common/utils_func.sh https://raw.githubusercontent.com/runshine/static_binary_tools/refs/heads/main/build/common/utils_func.sh && chmod +x /common/utils_func.sh
RUN curl -o /common/utils_func.sh https://raw.githubusercontent.com/runshine/static_binary_tools/refs/heads/main/build/common/arch_detect.sh && chmod +x /common/arch_detect.sh

COPY . /build/

RUN /build/build.sh

FROM busybox:latest

COPY --from=builder /build/install /build/install

CMD ["/bin/bash"]