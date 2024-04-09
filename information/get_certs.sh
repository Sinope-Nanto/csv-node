#!/usr/bin/env bash
#
# Copyright (c) 2023 ISCAS TCA @ by TCWG vonsky
#

set -x
sev -v

cd /opt/csv
csv_path=$(pwd)
if [ ! -f "$csv_path/hrk.cert" ]; then
    echo "hrk.cert not exist, start to export:"
    /opt/hygon/bin/hag csv export_cert_chain
else
    echo "hrk.cert already exist!"
fi

# parse one cert to certfile [hrk.cert -> hrk.cert.file]
# - arg1: certtype [hrk | hsk | cek | oca | pek | pdh]
parse_one_cert() {
    local certtype="${1}"
    cert_in="$csv_path/$certtype.cert"
    cert_out="$csv_path/$certtype.cert.file"

    if [ -f "$cert_in" ]; then
        presult=$(/opt/hygon/bin/hag csv parse_cert -in $cert_in)
        #echo $presult
        presult_new=$(echo "$presult" | sed 's/parse_cert command success!//g' | sed 's/\[csv\] Command successful!//g')
        echo "$presult_new" > $cert_out
    else
        echo "Error: $cert_in not exist, please check!"
    fi
}

main() {
    echo "start to parse hrk.cert:"
    parse_one_cert "hrk"

    echo "start to parse hsk.cert:"
    parse_one_cert "hsk"

    echo "start to parse cek.cert"
    parse_one_cert "cek"

    echo "start to parse oca.cert"
    parse_one_cert "oca"

    echo "start to parse pek.cert"
    parse_one_cert "pek"

    echo "start to parse pdh.cert"
    parse_one_cert "pdh"
}

main $@