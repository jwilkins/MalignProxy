# XXX: Doesn't log non-ssl (plugins not getting called for non-ssl connections)

MITM_ROOT = File.expand_path(File.dirname(__FILE__))
LOG_DIR = "#{MITM_ROOT}/logs"
Dir.mkdir(LOG_DIR) unless File.exists?(LOG_DIR)

require 'rubygems'
require 'mechanize'
require 'logger'
require 'net/http'
require 'webrick'
require 'webrick/https'
require 'webrick/httpproxy'
require 'webrick/log'
require "#{MITM_ROOT}/lib/quickcert"
require "#{MITM_ROOT}/lib/util"
require "#{MITM_ROOT}/lib/webrick_ssl_serialno"
require 'ruby-debug'

require 'plugin'

$DEBUG = false # sets debugging in webrick
$verbose = true # verbose debugging for mproxy
$count = -1

$plugins = load_plugins("#{MITM_ROOT}/plugins")

# enable modifications to unparsed_uri
class WEBrick::HTTPRequest
  def unparsed_uri=(str)
    @unparsed_uri = str
  end
end

# The proxy class, allocates a new HTTPServer for each requested server:port combo
# When an request arrives, makes a connection to the real server with Mechanize
# @spoofed_hosts is a hash of existing mitm server objects indexed by name
class SSLMITM < WEBrick::HTTPProxyServer
  def initialize(config)
    # XXX: agent should be per client
    @agent = WWW::Mechanize.new
    @agent.keep_alive = false
    @agent.verify_callback = Proc.new{ true }
    @spoofed_hosts = {}
    @mitm_port = 4433
    @retry_count = 0
    config[:Logger] = WEBrick::Log::new("#{LOG_DIR}/error.log", 5)
    super
  end

  def ssl_mitm(server, port)
    dest = "#{server}:#{port}"
    if @spoofed_hosts[dest]
      return @spoofed_hosts[dest].config[:Port]
    else
      begin
        # XXX: ask system for an unused port
        mitm = WEBrick::HTTPServer.new(:Port => @mitm_port, 
                                       :HTTPVersion => "1.0",
                                       :SSLEnable => true,
                                       :SSLVerifyClient => ::OpenSSL::SSL::VERIFY_NONE,
                                       :SSLCertName => [["C", "US"], ["O", server], ["CN", server] ])
      rescue
        @retry_count += 1
        @mitm_port += 1
        if @retry_count < 10
          retry
        else
          puts "Couldn't allocate port in SSLMITM, not retrying, too many tries already"
          exit
        end
      end

      @spoofed_hosts[dest] = mitm

      mitm.mount_proc('/') { |req,res|
        puts "Request: #{req.request_line}"
        $plugins.each { |plug|
          plug.request(req.request_line, req.header, req.body);
        }

        meth, url, ver = req.request_line.split(" ")
        # XXX: validate meth and ver
        agent = WWW::Mechanize.new
        agent.keep_alive = false
        puts "  doing #{meth.upcase}" if $verbose
        case meth.upcase
        when 'GET':
          r = agent.get("https://#{server}:#{port}#{url}", req.body, req.header)
        when 'HEAD':
          # FIXME: 2nd param should be QS params
          r = agent.head("https://#{server}:#{port}#{url}", {}, :headers => req.header)
        when 'POST':
          # FIXME: need to handle headers
          r = agent.post("https://#{server}:#{port}#{url}", req.body)
        else
          puts "Not handling #{meth} yet"
        end

        status_line = "HTTP/1.1 #{r.code} OK\r\n"
        puts "Response: #{status_line}"
        $plugins.each { |plug|
          # FIXME: get real HTTP ver and response msg
          plug.response(status_line, r.response, r.body);
        }

        puts "  Body:\n#{hexdump(r.body[0..31])}"
        res.body = r.body
        puts "  Header.keys: #{r.header.keys.sort.join(", ")}" if $verbose
        puts "  Connection #{r.header['connection']}" if $verbose
        r.header.keys.each { |k|
          unless k == 'content-encoding'
            res.header[k] = r.header[k]
          end
        }
      }

      st = Thread.new { mitm.start }
      return mitm.config[:Port]
    end
  end

  def proxy_connect(req, res)
    puts "SSLMITM.proxy_connect" if $verbose
    puts "  req.request_line: #{req.request_line}" if $verbose
    host, port = req.unparsed_uri.split(":")
    unless port then port = 443; end
    mitm_port = ssl_mitm(host, port)
    req.unparsed_uri = "127.0.0.1:#{mitm_port}"
    super
  end
end

s = SSLMITM.new(
  :Port => 9999,
  :HTTPVersion => "1.0",
  :MaxClients => 1,
  :ServerSoftware => "MalignProxy/0.0.1",
  :RequestCallback => Proc.new { |req,res|
    # Called on request data
    $count += 1
    puts "\n--- #{$count} #{'-'*40}"
    if $verbose
      puts "sslmitm.RequestCallback"
      puts "  #{req.request_line}"
    end
    meth, url, ver = req.request_line.split(" ")
    unless meth == 'CONNECT'
      $plugins.each { |plug|
        plug.request(req.request_line, req.header, req.body);
      }
    end
  },
  :ProxyContentHandler => Proc.new { |req,res|
    # Called for response data
    if $verbose
      puts "sslmitm.ProxyContentHandler" 
      puts "  #{req.request_line}"
    end
    meth, url, ver = req.request_line.split(" ")
    unless meth == 'CONNECT'
      $plugins.each { |plug|
        plug.response(res.status_line, res.header, res.body);
      }
    end
  }
);

trap("INT"){ s.shutdown }
s.start
