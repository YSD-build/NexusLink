#!/usr/bin/env bash
# NexusLink curl 对接脚本 - 内网穿透平台开放 API
# 用法: ./nexuslink.sh <api-key> <base-url> <command> [args...]
#
# 示例:
#   ./nexuslink.sh dev_key_789 http://127.0.0.1:7001 list-clients
#   ./nexuslink.sh dev_key_789 http://127.0.0.1:7001 create-client customer-a tok_a_1 3 1048576
#   ./nexuslink.sh dev_key_789 http://127.0.0.1:7001 traffic customer-a
#   ./nexuslink.sh dev_key_789 http://127.0.0.1:7001 delete-client customer-a
#   ./nexuslink.sh dev_key_789 http://127.0.0.1:7001 close-proxy web
#   ./nexuslink.sh dev_key_789 http://127.0.0.1:7001 create-api-key new_key_111 "note"
#   ./nexuslink.sh dev_key_789 http://127.0.0.1:7001 list-api-keys
#   ./nexuslink.sh dev_key_789 http://127.0.0.1:7001 delete-api-key new_key_111

set -e
API_KEY="$1"; BASE="$2"; CMD="$3"
[ -z "$API_KEY" ] || [ -z "$BASE" ] || [ -z "$CMD" ] && {
  echo "用法: $0 <api-key> <base-url> <command> [args...]"; exit 1
}

req() { # method path [json-body]
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS -X "$method" -H "X-API-Key: $API_KEY" -H "Content-Type: application/json")
  [ -n "$body" ] && args+=(-d "$body")
  curl "${args[@]}" "$BASE$path"
}

case "$CMD" in
  list-clients)   req GET /api/v1/clients ;;
  create-client)  # name token max_tunnels max_traffic_bytes
    req POST /api/v1/clients "{\"name\":\"$4\",\"token\":\"$5\",\"max_tunnels\":${6:-0},\"max_traffic_bytes\":${7:-0}}" ;;
  client)         req GET "/api/v1/clients/$4" ;;
  traffic)        req GET "/api/v1/clients/$4/traffic" ;;
  delete-client)  req DELETE "/api/v1/clients/$4" ;;
  close-proxy)    req POST /api/v1/proxies/close "{\"name\":\"$4\"}" ;;
  list-proxies)   req GET /api/v1/proxies ;;
  proxy)          req GET "/api/v1/proxies/$4" ;;
  create-proxy)   # name type remote_port local_port local_addr client_name
    req POST /api/v1/proxies "{\"name\":\"$4\",\"type\":\"$5\",\"remote_port\":$6,\"local_port\":$7,\"local_addr\":\"$8\",\"client_name\":\"$9\"}" ;;
  delete-proxy)   req DELETE "/api/v1/proxies/$4" ;;
  update-proxy)   # name field value（field: type/remote_port/local_addr/local_port/enabled）
    req PATCH "/api/v1/proxies/$4" "{\"$5\":$6}" ;;
  enable-proxy)   req POST "/api/v1/proxies/$4/enable" ;;
  disable-proxy)  req POST "/api/v1/proxies/$4/disable" ;;
  list-api-keys)  req GET /api/v1/api-keys ;;
  create-api-key) req POST /api/v1/api-keys "{\"key\":\"$4\",\"note\":\"$5\"}" ;;
  delete-api-key) req DELETE "/api/v1/api-keys/$4" ;;
  *)
    echo "未知命令: $CMD"; echo "可用: list-clients create-client client traffic delete-client list-proxies create-proxy proxy update-proxy delete-proxy enable-proxy disable-proxy close-proxy list-api-keys create-api-key delete-api-key"; exit 1 ;;
esac
echo
