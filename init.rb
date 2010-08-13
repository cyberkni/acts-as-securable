require File.join(File.dirname(__FILE__), %w{lib reader})
require File.join(File.dirname(__FILE__), %w{lib acts_as_protected})
require File.join(File.dirname(__FILE__), %w{lib in_model})

config = File.join(RAILS_ROOT, 'config', 'authorization.rb')
if File.readable? config
  ActiveRecord::Base.acl_manager = Authorization::Manager.new(File.open(config))
end

