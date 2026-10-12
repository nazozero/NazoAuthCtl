#!/bin/sh
printf '%s\n' "$*" >> "$(dirname "$0")/argv.txt"
case "$*" in
  *'remote transfer-stream')
    printf 'nazoauthctl-transfer-stream-1\n'
    while IFS= read -r input; do
      caller=$(printf '%s' "$input" | sed -n 's/.*"operation_id":"\([0-9a-fA-F-]*\)".*/\1/p')
      sed "s/__OPERATION_ID__/${caller:-none}/g" "$(dirname "$0")/response.json"
      printf '\n'
    done
    exit 0 ;;
esac
input=$(cat)
printf '%s' "$input" > "$(dirname "$0")/stdin.json"
caller=$(printf '%s' "$input" | sed -n 's/.*"operation_id":"\([0-9a-fA-F-]*\)".*/\1/p')
response="$(dirname "$0")/response.json"
case "$input" in
  *'"kind":"hello"'*)
    if [ -f "$(dirname "$0")/hello-response.json" ]; then
      response="$(dirname "$0")/hello-response.json"
    fi ;;
esac
sed "s/__OPERATION_ID__/${caller:-none}/g" "$response"
if [ -f "$(dirname "$0")/stderr.txt" ]; then
  cat "$(dirname "$0")/stderr.txt" >&2
fi
exit "$(cat "$(dirname "$0")/exitcode.txt")"
