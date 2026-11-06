ARG BASE=ubuntu:24.04
FROM ${BASE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libegl1 libgl1 libglib2.0-0t64 libdbus-1-3 libxkbcommon0 libxcb-cursor0 libxcb-icccm4 libxcb-keysyms1 libxcb-shape0 libxcb-xinerama0 libxcb-xkb1 libxkbcommon-x11-0 xvfb xauth weston
ENV HOME=/tmp LANG=C.UTF-8
WORKDIR /tmp
USER 1000:1000
