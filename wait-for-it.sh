#!/usr/bin/env bash
#   Use this script to test if a given TCP host/port are available

set -e

TIMEOUT=15
QUIET=0
WAIT_HOST=""
WAIT_PORT=""

echoerr() {
  if [[ "$QUIET" -ne 1 ]]; then echo "$@" 1>&2; fi
}

usage() {
  exitcode="$1"
  cat << USAGE >&2
Usage:
  $0 host:port [-t timeout] [-- command args]
  -q | --quiet                        Do not output any status messages
  -t TIMEOUT | --timeout=timeout      Timeout in seconds, zero for no timeout
  -- COMMAND ARGS                     Execute command with args after the test finishes
USAGE
  exit "$exitcode"
}

wait_for() {
  for i in $(seq $TIMEOUT) ; do
    nc -z "$WAIT_HOST" "$WAIT_PORT" > /dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

wait_for_wrapper() {
  if wait_for; then
    if [[ "$QUIET" -ne 1 ]]; then echo "Connection to $WAIT_HOST:$WAIT_PORT succeeded."; fi
  else
    echoerr "Timeout occurred after waiting $TIMEOUT seconds for $WAIT_HOST:$WAIT_PORT."
    exit 1
  fi
}

while [[ $# -gt 0 ]]
do
  case "$1" in
    *:* )
    WAIT_HOST=$(echo "$1" | cut -d : -f 1)
    WAIT_PORT=$(echo "$1" | cut -d : -f 2)
    shift 1
    ;;
    -q | --quiet)
    QUIET=1
    shift 1
    ;;
    -t)
    TIMEOUT="$2"
    if [[ "$TIMEOUT" = "" ]]; then break; fi
    shift 2
    ;;
    --timeout=*)
    TIMEOUT="${1#*=}"
    shift 1
    ;;
    --)
    shift
    exec "$@"
    ;;
    --help)
    usage 0
    ;;
    *)
    echoerr "Unknown argument: $1"
    usage 1
    ;;
  esac
done

if [[ "$WAIT_HOST" = "" || "$WAIT_PORT" = "" ]]; then
  echoerr "Error: you need to provide a host and port to test."
  usage 2
fi

wait_for_wrapper
