require 'sinatra'

def fibonacci(n)
  return n if n <= 1
  fibonacci(n - 1) + fibonacci(n - 2)
end

def c
  puts "hi"

  i = 0
  (0..10000).each do |n|
    i *= n + 3
    f = File.open('/')
    f.close
  end 
end

def b 
    c
end
def a 
    b
end

get '/' do
  Process.kill("CONT", Process.pid)
  a
  'hi'
end

get '/fib' do
  a = fibonacci(40)
  puts a
end

set :bind, '0.0.0.0'
set :port, 9494
