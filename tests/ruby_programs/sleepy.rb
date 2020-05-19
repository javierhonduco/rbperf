def infinite_loop
    while true
    end
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

$stdout.sync = true
puts "PID: #{Process.pid}"

a
