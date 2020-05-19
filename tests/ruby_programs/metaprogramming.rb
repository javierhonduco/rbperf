# Just for fun :) 

def a_11
    while true
    end
end

(1..10).each do |i|
    define_method "a_#{i}" do
        send("a_#{i+1}")
    end
end

Signal.trap("USR1") do
  a_1
end

$stdout.sync = true
puts "PID: #{Process.pid}"

sleep 30000
