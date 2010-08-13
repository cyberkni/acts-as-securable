# Copyright:: Copyright 2010 Google Inc.
# License:: All Rights Reserved.
# Original Author:: Brandon Liu (mailto:bdon@google.com)

require 'test_helper'

class Server < ActiveRecord::Base
  acts_as_protected
end

class AclAdministrationTest < ActiveSupport::TestCase
  context 'Testing acl administration' do
    context 'and creating/deleting authorization roles' do
      setup do
        input = %{
          authorization do
            secure :authorization_roles do
              creatable_by :$_admin
              destroyable_by :$_admin
            end
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        without_authorization do
          @admin = User.create!
          role = AuthorizationRole.create!(:name => "$_admin")
          AuthorizationGrant.create!(:authorization_role => role,
                                     :grantee => @admin)
          AuthorizationRole.create!(:name => "$arole1")
        end
      end

      teardown do
        delete_all_records
      end

      should 'let  admin create roles' do
        User.current = @admin
        AuthorizationRole.create!(:name => '$arole2')
      end

      should 'let admin delete roles' do
        User.current = @admin
        AuthorizationRole.find_by_name('$arole1').destroy
      end

    end

    context 'and creating/deleting authorization grants' do
      setup do
        input = %{ authorization do
                   end }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        without_authorization do
          @server = Server.create
          @user = User.create
          @inst_role = AuthorizationRole.create!(:name => '@acl_manager',
                                                 :securable => @server)
          @class_role = AuthorizationRole.create!(:name => '@@acl_manager',
                                                  :securable_type => 'Server')
          AuthorizationGrant.create!(:grantee => @user,
                                     :authorization_role => @inst_role)
          AuthorizationGrant.create!(:grantee => @user,
                                     :authorization_role => @class_role)
        end
      end

      should 'let role on associated instance create grant' do
        User.current = @user
        @sally = User.create
        input = %{
          authorization do
            secure :authorization_grants do
              creatable_by :@acl_manager,
                  :of_associated => {:authorization_role => :securable}
            end
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        assert_nothing_raised do
          # granting a grant on a specific instance
          AuthorizationGrant.create!(:grantee => @sally,
                                     :authorization_role => @inst_role)
        end
      end

      should 'let role on associated class create grant' do
        User.current = @user
        @sally = User.create
        input = %{
          authorization do
            secure :authorization_grants do
              creatable_by :@@acl_manager,
                  :of_class => {:authorization_role => :securable_type}
            end
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        assert_nothing_raised do
          AuthorizationGrant.create!(:grantee => @sally,
                                     :authorization_role => @class_role)
        end
      end

      teardown do
        delete_all_records
      end

    end
  end
end