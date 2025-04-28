
set -eu
set -o pipefail

cd "$(dirname "$0")"

git checkout ./litcode

./litcode --cat litcode.pl ./source.md > ./litcode.new.1

perl ./litcode.new.1 --cat litcode.pl ./source.md > ./litcode.new.2

diff ./litcode.new.1 ./litcode.new.2

cp -v ./litcode.new.2 ./litcode
