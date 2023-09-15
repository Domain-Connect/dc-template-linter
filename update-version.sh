#!/bin/sh

cat <<EOF >|./version.go
package main

const dcTemplateLinterVersion uint = $(git rev-list --count b4cfffd..)
EOF

exit $?
