# based on code from http://eignclass.org/hiki.rb?ruby+plugins

module PluginDecorator
  def def_field(*names)
    class_eval do
      names.each do |name|
        define_method(name) do |*args|
          case args.size
            when 0: instance_variable_get("@#{name}")
            else    instance_variable_set("@#{name}", *args)
          end
        end
      end
    end
  end
end

class Plugin
  @plugins = []

  def self.inherited(child)
    Plugin.plugins << child
  end

  class << self
    extend PluginDecorator
    attr_reader :plugins
    def_field :name, :author, :version, :desc
  end

  # Override to modify requests
  def request(req_line, headers, body)
  end

  # Override to modify responses
  def response(status_line, headers, body)
  end
end
