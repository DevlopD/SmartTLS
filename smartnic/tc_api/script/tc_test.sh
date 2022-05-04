# usage
# generate and delete 10000 tc rules with different match table and priority:
#   ./tc_test 0
# add and delete tc rules repeatedly:
#   ./tc_test 1

taskset -c 8 ./tc_test 0
