def a
  (1..100).each do |i|
    "asd" * i
  end
end


def b
  (1..50).each do |i|
    "asd" * i
  end
end

def c
  (1..25).each do |i|
    "asd" * i
  end
end

def main
  a
  b
  c
end


puts "PID: #{Process.pid}"

while true
  main
end
