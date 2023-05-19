FROM rust as builder

WORKDIR /opt/bin2ml

RUN env USER=root cargo init .

COPY Cargo.toml .
COPY Cargo.lock .
COPY src /opt/bin2ml/src

RUN cd /opt/bin2ml && \
    cargo install --locked --path . && \
    rm -rf /opt/bin2ml && \
    rm -rf /usr/local/cargo/registry

FROM rust

COPY --from=builder /usr/local/cargo/bin/bin2ml /usr/local/cargo/bin/bin2ml

CMD bin2ml --version