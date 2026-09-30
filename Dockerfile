# Reproducible build + benchmark environment for Nyx.
# Pins the toolchain so coverage/benchmark numbers are comparable across machines.
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential clang cmake git ca-certificates python3 python3-pip \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /nyx
COPY . .

# Build the engine and run the test suite as a build-time smoke check.
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    && cmake --build build -j \
    && ctest --test-dir build --output-on-failure

# Targets are fetched/built separately (network needed):
#   ./third_party/fetch_targets.sh
# then run the benchmark:
#   python3 bench/run_benchmark.py --target ... --corpus corpus/seeds

ENTRYPOINT ["/nyx/build/nyx"]
CMD ["--help"]
