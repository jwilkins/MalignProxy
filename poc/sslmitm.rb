# DONE: Choose new server port for each target server
# DONE: Generate root certificate and save, allowing user to add to cert store on first use
# DONE: Handle multiple connections
# DONE: Always close connections
require 'rubygems'
require 'mechanize'
require 'net/http'
require 'webrick'
require 'webrick/https'
require 'webrick/httpproxy'
require 'webrick/log'
require 'quickcert'
require 'ruby-debug'

$DEBUG = false # sets debugging in webrick
$verbose = true

def hexdump(str)
  i = 0
  res = []
  str.scan(/.{0,16}/m) { |match|
    res << (("%08x " % i) + match.unpack('H4'*8).join(' ') + "    " + match.tr('^A-Za-z0-9._', '.'))
    i += 16
  }
  res.join("\n")
end

# enable modifications to unparsed_uri
class WEBrick::HTTPRequest
  def unparsed_uri=(str)
    @unparsed_uri = str
  end
end

# monkey patch for ssl serial number issue - http://dev.rubyonrails.org/ticket/9551
module WEBrick::Utils
  def create_self_signed_cert(bits, cn, comment)
    unless defined?(@ca)
      puts "sslmitm: @ca undefined" if $verbose
      @ca_conf = {}
      @ca_conf[:hostname] = 'ca'
      @ca_conf[:domainname] = 'malign.proxy'
      @ca_conf[:password] = '0000'
      @ca_conf[:CA_dir] ||= File.join(Dir.pwd, "CA")

      @ca_conf[:keypair_file] ||= File.join(@ca_conf[:CA_dir], "private/cakeypair.pem")
      @ca_conf[:cert_file] ||= File.join(@ca_conf[:CA_dir], "cacert.pem")
      @ca_conf[:serial_file] ||= File.join(@ca_conf[:CA_dir], "serial")
      @ca_conf[:new_certs_dir] ||= File.join(@ca_conf[:CA_dir], "newcerts")
      @ca_conf[:new_keypair_dir] ||= File.join(@ca_conf[:CA_dir], "private/keypair_backup")
      @ca_conf[:crl_dir] ||= File.join(@ca_conf[:CA_dir], "crl")

      @ca_conf[:ca_cert_days] ||= 5 * 365 # five years
      @ca_conf[:ca_rsa_key_length] ||= 2048

      @ca_conf[:cert_days] ||= 365 # one year
      @ca_conf[:cert_key_length_min] ||= 1024
      @ca_conf[:cert_key_length_max] ||= 2048

      @ca_conf[:crl_file] ||= File.join(@ca_conf[:crl_dir], "#{@ca_conf[:hostname]}.crl")
      @ca_conf[:crl_pem_file] ||= File.join(@ca_conf[:crl_dir], "#{@ca_conf[:hostname]}.pem")
      @ca_conf[:crl_days] ||= 14

      if @ca_conf[:name].nil?
        @ca_conf[:name] = [
          ['C', 'US', OpenSSL::ASN1::PRINTABLESTRING],
          ['O', @ca_conf[:domainname], OpenSSL::ASN1::UTF8STRING],
          ['OU', @ca_conf[:hostname], OpenSSL::ASN1::UTF8STRING],
        ]
      end

      @ca = QuickCert.new(@ca_conf)
    end

    name = OpenSSL::X509::Name.new(cn)
    hostname = name.to_s.scan(/CN=([\w.]+)/)[0][0]
    puts "sslmitm: Creating cert for #{hostname}" if $verbose
    cert_config = { :type => 'server', :hostname => hostname }
    cert_file, cert, rsa = @ca.create_cert(cert_config)

    return [cert, rsa]
  end

  def create_self_signed_cert_orig_patch(bits, cn, comment)
    rsa = OpenSSL::PKey::RSA.new(bits){|p, n|
      case p
      when 0; $stderr.putc "."  # BN_generate_prime
      when 1; $stderr.putc "+"  # BN_generate_prime
      when 2; $stderr.putc "*"  # searching good prime,
                                # n = #of try,
                                # but also data from BN_generate_prime
      when 3; $stderr.putc "\n" # found good prime, n==0 - p, n==1 - q,
                                # but also data from BN_generate_prime
      else;   $stderr.putc "*"  # BN_generate_prime
      end
    }
    cert = OpenSSL::X509::Certificate.new
    cert.version = 3
    cert.serial = Time.now.to_i
    name = OpenSSL::X509::Name.new(cn)
    cert.subject = name
    cert.issuer = name
    cert.not_before = Time.now
    cert.not_after = Time.now + (365*24*60*60)
    cert.public_key = rsa.public_key

    ef = OpenSSL::X509::ExtensionFactory.new(nil,cert)
    ef.issuer_certificate = cert
    cert.extensions = [
      ef.create_extension("basicConstraints","CA:FALSE"),
      ef.create_extension("keyUsage", "keyEncipherment"),
      ef.create_extension("subjectKeyIdentifier", "hash"),
      ef.create_extension("extendedKeyUsage", "serverAuth"),
      ef.create_extension("nsComment", comment),
    ]
    aki = ef.create_extension("authorityKeyIdentifier",
                              "keyid:always,issuer:always")
    cert.add_extension(aki)
    cert.sign(rsa, OpenSSL::Digest::SHA1.new)

    return [ cert, rsa ]
  end
  module_function :create_self_signed_cert
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

MITM_ROOT = File.expand_path(File.dirname(__FILE__))
LOG_DIR = "#{MITM_ROOT}/logs"
Dir.mkdir(LOG_DIR) unless File.exists?(LOG_DIR)

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
    req.header.delete('accept-encoding')
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
