FROM ubuntu:24.04@sha256:cd1dba651b3080c3686ecf4e3c4220f026b521fb76978881737d24f200828b2b
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends python3 python3-venv python3-dev binutils patchelf curl ca-certificates file libmagic1t64 libglib2.0-0t64 libegl1 libgl1 libxkbcommon0 libdbus-1-3 libxcb-cursor0 libxcb-icccm4 libxcb-keysyms1 libxcb-shape0 libxcb-xinerama0 libxcb-xkb1 libxkbcommon-x11-0 xvfb xauth libwayland-client0 libwayland-cursor0 libwayland-egl1 weston zsync desktop-file-utils
RUN python3 -m venv /opt/build
ENV PATH=/opt/build/bin:$PATH
RUN pip install 'uv==0.9.8' 'pyinstaller==6.16.0' 'pyinstaller-hooks-contrib==2026.9'
WORKDIR /src
