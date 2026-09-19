#!/usr/bin/env bash
set -euo pipefail

# Section 6 / Table 18: LENS generalizability across 16 non-Diameter
# protocols (857 fields). BGP comprises core, EVPN, and FlowSpec components;
# D-Bus comprises bus-field and interface-method components.

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PYTHON="${PYTHON:-python}"
SERVICE="${SERVICE:-gpt5.4}"
WORKERS="${WORKERS:-7}"
ROUNDS="${ROUNDS:-3}"
PROTOCOLS="${PROTOCOLS:-sip bgp mqtt dhcp radius http2 dns snmp sle oci wayland modbus fuse rtsp amqp dbus}"
OUTPUT_ROOT="${OUTPUT_ROOT:-output/paper/generalizability}"

selected() {
  local protocol="$1"
  [[ " ${PROTOCOLS} " == *" ${protocol} "* ]]
}

run_component() {
  local paper_protocol="$1"
  local output_name="$2"
  local seed_name="$3"
  local protocol_id="$4"
  local target_name="$5"
  local attack_seed="$6"
  local safe_seed="$7"

  if ! selected "${paper_protocol}"; then
    return
  fi

  "${PYTHON}" -m src.generalizability \
    --service "${SERVICE}" \
    --seed-examples "data/non_diameter/seed/${seed_name}.md" \
    --attack-indices "${attack_seed}" \
    --safe-indices "${safe_seed}" \
    --attack-side all \
    --rounds "${ROUNDS}" \
    --workers "${WORKERS}" \
    --target-paths-file "data/non_diameter/target/${target_name}" \
    --target-side all \
    --protocol "${protocol_id}" \
    --output-dir "${OUTPUT_ROOT}/${output_name}"
}

run_component sip sip sip sip sip_header_targets.json 1 5

run_component bgp bgp/core bgp bgp bgp_attribute_targets.json 1 7
run_component bgp bgp/evpn bgp_evpn bgp_evpn bgp_evpn_targets.json 1 7
run_component bgp bgp/flowspec bgp_flowspec bgp_flowspec bgp_flowspec_targets.json 1 7

run_component mqtt mqtt mqtt mqtt mqtt_v5_field_targets.json 1 5
run_component dhcp dhcp dhcp dhcp dhcp_option_targets.json 1 5
run_component radius radius radius radius radius_attribute_targets.json 1 5
run_component http2 http2 http2 http2 http2_frame_targets.json 1 5
run_component dns dns dns dns dns_rr_targets.json 1 5
run_component snmp snmp snmp snmp snmp_binding_targets.json 1 5
run_component sle sle sle sle sle_parameter_targets.json 1 4
run_component oci oci oci oci oci_setting_targets.json 1 5
run_component wayland wayland wayland wayland wayland_argument_targets.json 1 5
run_component modbus modbus modbus modbus modbus_register_targets.json 1 5
run_component fuse fuse fuse fuse fuse_field_targets.json 1 5
run_component rtsp rtsp rtsp rtsp rtsp_targets.json 1 6
run_component amqp amqp amqp amqp amqp_field_targets.json 1 2

run_component dbus dbus/bus_fields dbus dbus dbus_bus_field_targets_v2.json 1 6
run_component dbus dbus/methods dbus dbus dbus_method_targets.json 1 6
