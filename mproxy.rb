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
$verbose = true

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
    super
    # XXX: agent should be per client
    @agent = WWW::Mechanize.new
    @agent.keep_alive = false
    @agent.verify_callback = Proc.new{ true }
    @spoofed_hosts = {}
    @mitm_port = 4433
    @retry_count = 0
    config[:Logger] = WEBrick::Log::new('error.log', 5)
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
          puts "Not retrying, too many tries already"
          exit
        end
      end

      @spoofed_hosts[dest] = mitm

      mitm.mount_proc('/') { |req,res|
        puts ""
        puts "-" * 20
        puts ""
        meth, url, ver = req.request_line.split(" ")
        # XXX: validate meth and ver
        puts "SSLMITM.ssl_mitm.mount_proc: #{req.request_line}"
        agent = WWW::Mechanize.new
        agent.keep_alive = false
        case meth.upcase
        when 'GET':
          puts "  doing GET" if $verbose
          r = agent.get("https://#{server}:#{port}#{url}", req.body, req.header)
        when 'HEAD':
          puts "  doing HEAD" if $verbose
          r = agent.head("https://#{server}:#{port}#{url}", req.body, req.header)
        when 'POST':
          puts "  doing POST" if $verbose
          r = agent.post("https://#{server}:#{port}#{url}", req.body, req.header)
        else
          puts "Not handling #{meth} yet"
        end
        #puts "r.body: #{r.body[0..20].unpack('h2*')}" if $verbose
        puts "r.body:\n#{hexdump(r.body[0..32])}"
        res.body = r.body
        puts "r.header.keys: #{r.header.keys.sort.join(", ")}" if $verbose
        puts "r.connection #{r.header['connection']}"
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
    puts "in hijacked proxy_connect, req.request_line: #{req.request_line}" if $verbose
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
    puts ""
    puts "-" * 60
    puts "sslmitm: in RequestCallback" if $verbose
    $count ||= 0
    $plugins.each { |plug|
      plug.request(req.request_line, req.header, req.body);
    }
    open("#{LOG_DIR}/#{$count}-request", "wb+") { |f|
      f << req.request_line
      f << req.raw_header
      f << "\r\n"
      f.write(req.body) if req.body && req.body.length > 0
    }
  },
  :ProxyContentHandler => Proc.new { |req,res|
    puts "-" * 40
    puts "sslmitm: in ProxyContentHandler" if $verbose
    $plugins.each { |plug|
      plug.response(res.status_line, res.header, res.body);
    }
    open("#{LOG_DIR}/#{$count}-response", "wb+") { |f|
      f << res.status_line
      res.header.keys.each { |k|
        f << "#{k.capitalize}: #{res.header[k]}\r\n"
      }
      f << "\r\n"
      f.write(res.body) if res.body && res.body.length > 0
    }
    $count += 1
  }
);

trap("INT"){ s.shutdown }
s.start
