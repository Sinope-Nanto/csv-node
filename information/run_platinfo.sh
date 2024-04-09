#!/usr/bin/env bash
#
# Copyright (c) 2023 ISCAS TCA @ by TCWG vonsky
#

set -x
set -v

cd /opt/csv
./get_certs.sh
python3 get_platbaseinfo.py

