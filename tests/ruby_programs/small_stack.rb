def infinite_loop
  File.open("/")
end

def c
    infinite_loop
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
