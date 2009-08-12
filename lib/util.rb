def load_plugins(dir)
  unless File::stat(dir).directory?
    puts "Plugin dir #{dir} isn't a directory"
    exit
  end

  puts "Loading plugins:"
  Dir["#{dir}/*.rb"].each{ |plug| load plug; }
  loaded_plugins = []
  Plugin.plugins.each { |plug|
    puts "  - #{plug.name}"
    loaded_plugins << plug.new
  }
  loaded_plugins
end

def hexdump(str)
  i = 0
  res = []
  str.scan(/.{0,16}/m) { |match|
    res << "%08x  %-40s %-16s" % [i, match.unpack('H4'*8).join(' '), match.tr('^ -~', '.')]
    i += 16
  }
  res.join("\n")
end


