# hadolint global ignore=DL3006,DL3013,DL3018,DL3041,DL3059

FROM redhat/ubi9-minimal AS base

ARG MARCH=native

WORKDIR /build

RUN echo install_weak_deps=0 >> /etc/dnf/dnf.conf && \
    microdnf upgrade -y && \
    microdnf install -y \
        go-toolset \
        python-numpy \
        unzip \
    && \
    ARCH=$(grep -q avx2 /proc/cpuinfo && [ "${MARCH}" = "native" ] || [ "${MARCH}" = "x86-64-v3" ] && echo "avx2" || echo "x86_64") && \
    curl -so plink2.zip "https://s3.amazonaws.com/plink2-assets/plink2_linux_${ARCH}_latest.zip" && \
    unzip plink2.zip && \
    rm plink2.zip vcf_subset && \
    microdnf remove -y unzip && \
    microdnf clean all

COPY go.* .
RUN go mod download

COPY . .
WORKDIR /build/lmm
RUN --mount=type=cache,target=/root/.cache/go-build go build .

CMD ["../scripts/demo.sh"]
