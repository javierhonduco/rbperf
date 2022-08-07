def cpu
  (0..1000).each do
  end
end

def hog
  (0..1000).each do
  end
end

def program
  (0..1000).each do
  end
end


def c1
  cpu
end

def b1
  c1
end

def a1
  b1
end

def c2
  hog
end

def b2
  c2
end

def a2
  b2
end

def c3
  program
end

def b3
  c3
end

def a3
  b3
end

$stdout.sync = true
puts "PID: #{Process.pid}"

while true
  a1
  a2
  a3
end
