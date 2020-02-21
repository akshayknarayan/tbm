FROM rust:1.40

WORKDIR /app
ADD ./target/release/pingserver ./pingserver
ADD ./target/release/pingclient ./pingclient
CMD ["server", "--addr", "0.0.0.0:4242"]

# TODO following approach means super long build times
#ADD . .
#RUN rustup component add rustfmt
#RUN cargo build --release
#
#ENTRYPOINT ["cargo", "run", "--release", "--bin"]
#CMD ["server", "--", "--addr", "0.0.0.0:4242"]
