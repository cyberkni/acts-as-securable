# Copyright:: Copyright 2010 Google Inc.
# License:: All Rights Reserved.
# Original Author:: Brandon Liu (mailto:bdon@google.com)
#
class ActsAsProtectedMigrationGenerator < Rails::Generator::Base
  def manifest
    record do |m|
      m.migration_template 'migration.rb', 'db/migrate',
          :migration_file_name => 'create_authorization_models'
      m.template 'authorization_grant.rb', 'app/models/authorization_grant.rb'
      m.template 'authorization_role.rb', 'app/models/authorization_role.rb'
    end
  end
end