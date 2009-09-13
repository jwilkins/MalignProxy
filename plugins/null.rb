require "#{File.dirname(__FILE__)}/../plugin.rb"

class NullPlugin < Plugin
  name "Null"
  desc "Does nothing, just an example"
  author "Jonathan Wilkins"
  version "0.0.1"

  def initialize
    puts "    Inside NullPlugin.initializing" if $verbose
    super
  end

  def request(req_line, headers, body)
    puts "    Inside NullPlugin.request" if $verbose
  end
end
