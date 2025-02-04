FROM gramineproject/gramine:v1.5@sha256:615849089db84477f03cd13209c08eaf6b6a3a68b4df733e097db56781935589

# Install Rust 1.80 and build dependencies
RUN apt-get update && apt-get install -y \
    build-essential=12.8ubuntu1.1 \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain 1.80 -y
ENV PATH="/root/.cargo/bin:${PATH}"

ARG SGX=1
ENV SGX=$SGX
ARG DEBUG=0
ENV DEBUG=$DEBUG
ARG DEV_MODE=0
ENV DEV_MODE=$DEV_MODE
ARG GRAMINE=gramine-sgx
ENV GRAMINE=${GRAMINE}
ENV RUST_LOG=info

WORKDIR /app
COPY ./ /app

RUN gramine-sgx-gen-private-key
RUN make all
ENTRYPOINT [ "make", "run-provider" ]
