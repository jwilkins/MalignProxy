require "#{File.dirname(__FILE__)}/../plugin.rb"

class NoGzipPlugin < Plugin
  name "No gzip"
  desc "Removes accept-encoding header from requests"
  author "Jonathan Wilkins"
  version "0.0.1"

  def request(req_line, headers, body)
    if headers.include?('accept-encoding')
      puts "    Removing accept-encoding header in NoGzipPlugin" if $verbose
      headers.delete('accept-encoding')
    end
  end
end
