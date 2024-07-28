FROM rust:1.79 as rust-cacher

WORKDIR /build
RUN apt-get update \
    && apt-get install -y libpq-dev git cmake
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo install cargo-chef
COPY recipe.json .
#COPY .git .git
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo chef cook --release --recipe-path recipe.json

FROM rust:1.79 as rust-builder

WORKDIR /build

COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
COPY .cargo .cargo
#COPY .git .git

COPY src src
COPY migrations migrations
COPY diesel.toml diesel.toml
COPY --from=rust-cacher /build/target target

RUN apt-get update \
    && apt-get install -y libpq-dev git cmake
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo build --release --bin ssu_mgmt

# App assembling
FROM debian:bookworm-slim
ARG APP=/usr/src/app

RUN apt-get update \
    && apt-get install -y ca-certificates tzdata curl libpq-dev \
    && rm -rf /var/lib/apt/lists/*


EXPOSE 8080

ENV TZ=Etc/UTC
ENV APP_USER=app

RUN groupadd $APP_USER \
    && useradd -g $APP_USER $APP_USER \
    && mkdir -p ${APP}

COPY --from=rust-builder /build/target/release/ssu_mgmt ${APP}/ssu_mgmt

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}

CMD ["./ssu_mgmt"]
