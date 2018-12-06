#!/usr/bin/env bash
# ./scripts/change_dependency_name.sh <new_dependency_path>
# change some.repo to some.2.repo
# ./scripts/change_dependency_name.sh <old_dependency_path> <new_dependency_path>

# original repository
src_path='github.com/xwb1989/sqlparser'
dst_path=$1
if [[ "$#" == 0 ]] ;
then
    echo "You must pass new name for dependency or two for old and new";
    exit 1
fi

if [[ "$#" -ne 1 ]]; then
  src_path=$1;
  dst_path=$2;
fi

for i in $(find . -type f | grep -v git | grep -v scripts/); do sed -i "s=$src_path=$dst_path=g" $i; done