#! /bin/sh

out="$2"
package="$1"

if [ -z "$out" ]; then
    echo "gitref.sh:fatal: no output file given" 1>&2
    exit 1
fi

if [ -z "$package" ]; then
    echo "gitref.sh:fatal: no package given" 1>&2
    exit 1
fi

ref=`git rev-parse HEAD`

echo "package $package" > "$out"
echo "const CommitRef = \"$ref\"" >> "$out"