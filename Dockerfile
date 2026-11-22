FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake pkg-config libmicrohttpd-dev libcurl4-openssl-dev libcjson-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B build && cmake --build build --parallel

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libmicrohttpd12 libcurl4 libcjson1 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/build/rupeesense /app/rupeesense
COPY static /app/static
ENV PORT=8080
EXPOSE 8080
CMD ["/app/rupeesense"]
