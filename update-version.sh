#!/bin/sh

cat <<EOF >|./internal/version.go
package internal

const ProjectVersion uint = $(git rev-list --count b4cfffd..)
EOF

exit $?
