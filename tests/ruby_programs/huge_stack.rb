def infinite_loop
  File.open("/")
end
def a150
	infinite_loop
end
def a149
	a150
end
def a148
	a149
end
def a147
	a148
end
def a146
	a147
end
def a145
	a146
end
def a144
	a145
end
def a143
	a144
end
def a142
	a143
end
def a141
	a142
end
def a140
	a141
end
def a139
	a140
end
def a138
	a139
end
def a137
	a138
end
def a136
	a137
end
def a135
	a136
end
def a134
	a135
end
def a133
	a134
end
def a132
	a133
end
def a131
	a132
end
def a130
	a131
end
def a129
	a130
end
def a128
	a129
end
def a127
	a128
end
def a126
	a127
end
def a125
	a126
end
def a124
	a125
end
def a123
	a124
end
def a122
	a123
end
def a121
	a122
end
def a120
	a121
end
def a119
	a120
end
def a118
	a119
end
def a117
	a118
end
def a116
	a117
end
def a115
	a116
end
def a114
	a115
end
def a113
	a114
end
def a112
	a113
end
def a111
	a112
end
def a110
	a111
end
def a109
	a110
end
def a108
	a109
end
def a107
	a108
end
def a106
	a107
end
def a105
	a106
end
def a104
	a105
end
def a103
	a104
end
def a102
	a103
end
def a101
	a102
end
def a100
	a101
end
def a99
	a100
end
def a98
	a99
end
def a97
	a98
end
def a96
	a97
end
def a95
	a96
end
def a94
	a95
end
def a93
	a94
end
def a92
	a93
end
def a91
	a92
end
def a90
	a91
end
def a89
	a90
end
def a88
	a89
end
def a87
	a88
end
def a86
	a87
end
def a85
	a86
end
def a84
	a85
end
def a83
	a84
end
def a82
	a83
end
def a81
	a82
end
def a80
	a81
end
def a79
	a80
end
def a78
	a79
end
def a77
	a78
end
def a76
	a77
end
def a75
	a76
end
def a74
	a75
end
def a73
	a74
end
def a72
	a73
end
def a71
	a72
end
def a70
	a71
end
def a69
	a70
end
def a68
	a69
end
def a67
	a68
end
def a66
	a67
end
def a65
	a66
end
def a64
	a65
end
def a63
	a64
end
def a62
	a63
end
def a61
	a62
end
def a60
	a61
end
def a59
	a60
end
def a58
	a59
end
def a57
	a58
end
def a56
	a57
end
def a55
	a56
end
def a54
	a55
end
def a53
	a54
end
def a52
	a53
end
def a51
	a52
end
def a50
	a51
end
def a49
	a50
end
def a48
	a49
end
def a47
	a48
end
def a46
	a47
end
def a45
	a46
end
def a44
	a45
end
def a43
	a44
end
def a42
	a43
end
def a41
	a42
end
def a40
	a41
end
def a39
	a40
end
def a38
	a39
end
def a37
	a38
end
def a36
	a37
end
def a35
	a36
end
def a34
	a35
end
def a33
	a34
end
def a32
	a33
end
def a31
	a32
end
def a30
	a31
end
def a29
	a30
end
def a28
	a29
end
def a27
	a28
end
def a26
	a27
end
def a25
	a26
end
def a24
	a25
end
def a23
	a24
end
def a22
	a23
end
def a21
	a22
end
def a20
	a21
end
def a19
	a20
end
def a18
	a19
end
def a17
	a18
end
def a16
	a17
end
def a15
	a16
end
def a14
	a15
end
def a13
	a14
end
def a12
	a13
end
def a11
	a12
end
def a10
	a11
end
def a9
	a10
end
def a8
	a9
end
def a7
	a8
end
def a6
	a7
end
def a5
	a6
end
def a4
	a5
end
def a3
	a4
end
def a2
	a3
end
def a1
	a2
end

Signal.trap("USR1") do
  a1
end

$stdout.sync = true
puts "PID: #{Process.pid}"

sleep 30000
