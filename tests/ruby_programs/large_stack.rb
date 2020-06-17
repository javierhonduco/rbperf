def top
  File.open("/")
end

def a33
    top
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
