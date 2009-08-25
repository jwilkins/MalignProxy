require "#{File.dirname(__FILE__)}/../plugin.rb"

class LogPlugin < Plugin
  name "Log"
  desc "Logs requests and responses"
  author "Jonathan Wilkins"
  version "0.0.1"

  def request(req_line, headers, body)
    open("#{LOG_DIR}/#{$count}-request", "wb+") { |f|
      f << req_line
      headers.keys.each { |k|
        f << "#{k.capitalize}: #{headers[k]}\r\n"
      }
      f << "\r\n"
      f.write(body) if body && body.length > 0
    }
  end

  def response(status_line, headers, body)
    open("#{LOG_DIR}/#{$count}-response", "wb+") { |f|
      f << status_line
      headers.keys.each { |k|
        f << "#{k.capitalize}: #{headers[k]}\r\n"
      }
      f << "\r\n"
      f.write(body) if body && body.length > 0
    }
  end
end
