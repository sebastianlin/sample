#!/bin/bash

package=""  # Default to empty package
target=""  # Default to empty target

# Parse options to the `pip` command
# ':' disable the default error handling
# Support '-h'
while getopts ":h" opt; do
  case ${opt} in
    h )
      echo "Usage:"
      echo "    pip -h                      Display this help message."
      echo "    pip install <package>       Install <package>."
      exit 0
      ;;
   \? )
     echo "Invalid Option: -$OPTARG" 1>&2
     exit 1
     ;;
  esac
done
shift $((OPTIND -1))

# Support 'install xxx' and 'install xxx -t yyy'
subcommand=$1; shift  # Remove 'pip' from the argument list
case "$subcommand" in
  # Parse options to the install sub command
  install)
    package=$1; shift  # Remove 'install' from the argument list

	if [ "$1" == "" ]; then
       echo -n "install package, \""
       echo -n $package
       echo "\"."
	fi

    # Process package options
    while getopts ":t:" opt; do
      case ${opt} in
        t )
          target=$OPTARG

          echo -n "install package, \""
          echo -n $package
          echo -n "\", with target, \""
          echo -n $target
          echo "\"."
          ;;
        \? )
          echo "Invalid Option: -$OPTARG" 1>&2
          exit 1
          ;;
        : )
          echo "Invalid Option: -$OPTARG requires an argument" 1>&2
          exit 1
          ;;
      esac
    done
    shift $((OPTIND -1))
    ;;
esac

