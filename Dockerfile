FROM gramineproject/gramine:1.9-jammy@sha256:84b3d222e0bd9ab941f0078a462af0dbc5518156b99b147c10a7b83722ac0c38

# Install Rust 1.85 and build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain 1.85 -y
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
