FROM datadog/docker-library:musl-latest

ARG NGINX_VERSION="1.27.0"
ARG ARCH="aarch64"
ARG WAF="OFF"
ARG BUILDTYPE="RelWithDebInfo"

COPY . /builddir
WORKDIR builddir

RUN make build-musl-aux

RUN mkdir -p /datadog
RUN mv .musl-build/ngx_http_datadog_module.so /datadog/ngx_http_datadog_module.so

WORKDIR /
RUN rm -R /builddir

RUN printf '#!/bin/sh\nmkdir -p /modules_mount\ncp /datadog/ngx_http_datadog_module.so /modules_mount/ngx_http_datadog_module.so\n' >> /usr/local/bin/init_module.sh
RUN chmod +x /usr/local/bin/init_module.sh
