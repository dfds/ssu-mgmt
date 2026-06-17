FROM node:22-alpine AS frontend-builder

WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM rust:1.91 as rust-cacher

WORKDIR /build/backend
RUN apt-get update \
    && apt-get install -y libpq-dev git cmake
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo install cargo-chef
COPY backend/recipe.json .
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo chef cook --release --recipe-path recipe.json

FROM rust:1.91 as rust-builder

WORKDIR /build/backend

COPY backend/Cargo.toml ./Cargo.toml
COPY backend/Cargo.lock ./Cargo.lock
COPY backend/.cargo .cargo

COPY backend/src src
COPY backend/migrations migrations
COPY backend/diesel.toml diesel.toml
COPY --from=frontend-builder /build/backend/dist ./dist
COPY --from=rust-cacher /build/backend/target target

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

COPY --from=rust-builder /build/backend/target/release/ssu_mgmt ${APP}/ssu_mgmt

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}

CMD ["./ssu_mgmt"]
