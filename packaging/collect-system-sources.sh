#!/bin/sh
set -eu
sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources
apt-get update > /tmp/apt-sources.log
python /scripts/collect_system_sources.py /bundle /out/system
