MAX_FRAMES = 100

eval "def a_#{MAX_FRAMES}
    puts 'hi'
end"

(1...MAX_FRAMES).each do |i|
    eval "def a_#{i}
    a_#{i+1}
    end"
end


$stdout.sync = true
puts "PID: #{Process.pid}"

while true
    a_1
end