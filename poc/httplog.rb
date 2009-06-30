# Quick basic proxy, just strips accept-encoding header and dumps
# to files in the local directory using the WebScarab naming convention
# (0-request, 0-response ...)
require 'net/http'
require 'webrick/httpproxy'

s = WEBrick::HTTPProxyServer.new(
  :Port => 9999, 
  :RequestCallback => Proc.new{|req,res|
    $count ||= 0
    req.header.delete('accept-encoding')
    open("#{$count}-request", "wb+") { |f|
      f << "#{req.request_line}#{req.raw_header}\r\n#{req.body}"
    }
  },
  :ProxyContentHandler => Proc.new{|req,res|
    open("#{$count}-response", "wb+") { |f|
      f << res.status_line
      res.header.keys.each { |k|
        f << "#{k.capitalize}: #{res.header[k]}\r\n"
      }
      f << "\r\n#{res.body}"
    }
    $count += 1
  }
);
trap("INT"){
  s.shutdown
}
s.start
