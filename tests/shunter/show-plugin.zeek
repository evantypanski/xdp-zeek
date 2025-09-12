# @TEST-EXEC: zeek -NN XDP::Shunter |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
