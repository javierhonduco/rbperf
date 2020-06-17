def top
  File.open("/")
end

def c
    top
end

def b
    c
end

def a
    b
end


Signal.trap("USR1") do
  a
end

$stdout.sync = true
puts "PID: #{Process.pid}"

sleep 30000
