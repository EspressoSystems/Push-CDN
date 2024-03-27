# Use a temporary builder image
FROM docker.io/rust:1.76-bookworm as BUILDER

# Set up the working directory
WORKDIR /build
COPY . .

# Build our example (all of them for caching)
RUN cargo build --profile release -p cdn-broker -p cdn-client -p cdn-marshal

# Use a minimal image for the final build
FROM debian:bookworm as RUNNER

# Install necessary dependencies
RUN apt-get update && apt-get install libcurl4 -y

# Set the Rust log level
ENV RUST_LOG=info

# Copy the built binary from the builder image
COPY --from=BUILDER ./build/target/release/cdn-client /bin/cdn-client

# Set the entrypoint
ENTRYPOINT ["cdn-client"]