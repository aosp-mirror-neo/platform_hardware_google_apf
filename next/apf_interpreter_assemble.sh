#!/bin/bash
set -e
set -u

do_assemble() {
  local -r RE_INCLUDE='^#include "([a-z_]+[.]h)"$'

  local line
  while IFS='' read -r line; do
    if [[ "${line}" =~ ${RE_INCLUDE} ]]; then
      local include_name="${BASH_REMATCH[1]}"
      case "${include_name}" in
        apf_interpreter.h)
          echo "${line}"
          ;;
        *)
          echo "// Begin include of ${include_name}"
          cat "${include_name}"
          echo "// End include of ${include_name}"
          ;;
      esac
    else
      echo "${line}"
    fi
  done < apf_interpreter_source.c
}

do_test() {
  diff -q <(do_assemble) apf_interpreter.c
}

main() {
  cd "${0%/*}"

  local -r me="${0##*/}"
  case "${me}" in
    apf_interpreter_assemble.sh)
      do_assemble > apf_interpreter.c
      ;;
    apf_assemble_test.sh)
      do_test
      ;;
    *)
      echo "Unknown $0" 1>&2
      return 1
      ;;
  esac
}

main "$@"; exit
