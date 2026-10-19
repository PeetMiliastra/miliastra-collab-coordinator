FROM rust:1.90-bookworm AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/core ./crates/core
COPY src ./src
COPY migrations ./migrations
RUN cargo build --locked --release -p miliastra-service
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/miliastra-service /usr/local/bin/
USER 65534:65534
ENV BIND_ADDR=0.0.0.0:8787
EXPOSE 8787
CMD ["miliastra-service"]
