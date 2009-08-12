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

  module_function :create_self_signed_cert
end


