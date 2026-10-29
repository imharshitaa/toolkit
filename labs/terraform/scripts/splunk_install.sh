#!/bin/bash
# Bootstrap script for Splunk Enterprise on Amazon Linux 2.
#
# Templated by Terraform's templatefile() in aws_lab.tf — the only value
# substituted in is the admin password, supplied via the splunk_password
# variable (TF_VAR_splunk_password) and never hardcoded in source control.
#
# Shell variables below use $${...} rather than ${...} so Terraform leaves
# them untouched and only substitutes its own template variable.
set -euo pipefail

SPLUNK_VERSION="9.2.1"
SPLUNK_BUILD="78803f08aabb"
SPLUNK_RPM="splunk-$${SPLUNK_VERSION}-$${SPLUNK_BUILD}-linux-2.6-x86_64.rpm"
SPLUNK_URL="https://download.splunk.com/products/splunk/releases/$${SPLUNK_VERSION}/linux/$${SPLUNK_RPM}"
# Check https://www.splunk.com/en_us/download/splunk-enterprise.html for the
# current version/build before applying — Splunk removes old release
# artifacts from this URL over time.

cd /tmp
curl -sSL -o "$${SPLUNK_RPM}" "$${SPLUNK_URL}"
rpm -i "$${SPLUNK_RPM}"

/opt/splunk/bin/splunk start --accept-license --no-prompt --answer-yes \
  --seed-passwd '${splunk_password}'

/opt/splunk/bin/splunk enable boot-start

# Enable the HTTP Event Collector so ToolKit's SOC/splunk simulate module can
# deliver synthetic events to this instance over HTTPS.
/opt/splunk/bin/splunk http-event-collector enable \
  -uri https://localhost:8089 \
  -auth "admin:${splunk_password}"
