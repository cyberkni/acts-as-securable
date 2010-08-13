# Copyright:: Copyright 2010 Google Inc.
# License:: All Rights Reserved.
# Original Author:: Brandon Liu (mailto:bdon@google.com)

# test the ACL query system

require 'test_helper'

class Server < ActiveRecord::Base
  acts_as_protected
  has_many :ownerships
  has_many :users, :through => :ownerships
end

class Ownership < ActiveRecord::Base
  acts_as_protected
  belongs_to :user
  belongs_to :server
end

class UnderScore < ActiveRecord::Base
  acts_as_protected
end

class ClassRoleTest < ActiveSupport::TestCase

# No permission cases
  context 'In configurations defining class roles,' do

    teardown do
      delete_all_records
    end

    context 'a configuration that grants no permissions' do
      setup do
        input = %{
          authorization do
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        without_authorization do
          @secured_server = Server.create
          @role_less_user = User.create
          @manager_user = User.create
          @manager_role = AuthorizationRole.create(:securable_type => 'Server',
                                                   :name => '@@manager')
          AuthorizationGrant.create(:authorization_role => @manager_role,
                                    :grantee => @manager_user)
        end
      end

      should 'not permit anonymous user to create' do
        User.current = nil
        assert_raise Authorization::SecurityError do
          Server.create
        end
      end

      should 'not permit anonymous user to update' do
        User.current = nil
        assert_raise Authorization::SecurityError do
          @secured_server.name = 'a name'
          @secured_server.save
        end
      end

      should 'not permit anonymous user to destroy' do
        User.current = nil
        assert_raise Authorization::SecurityError do
          @secured_server.destroy
        end
      end

      should 'not permit role-less user to create' do
        User.current = @role_less_user
        assert_raise Authorization::SecurityError do
          Server.create
        end
      end

      should 'not permit role-less user to update' do
        User.current = @role_less_user
        assert_raise Authorization::SecurityError do
          @secured_server.name = 'a name'
          @secured_server.save
        end
      end

      should 'not permit role-less user to destroy' do
        User.current = @role_less_user
        assert_raise Authorization::SecurityError do
          @secured_server.destroy
        end
      end

      should 'not permit user with manager role to create' do
        User.current = @manager_user
        assert_raise Authorization::SecurityError do
          Server.create
        end
      end

      should 'not permit user with manager role to update' do
        User.current = @manager_user
        assert_raise Authorization::SecurityError do
          @secured_server.name = 'a name'
          @secured_server.save
        end
      end

      should 'not permit user with manager role to destroy' do
        User.current = @manager_user
        assert_raise Authorization::SecurityError do
          @secured_server.destroy
        end
      end

    end

  # Basic Configuration

    context 'a configuration granting basic permissions' do

      setup do
        input = %{
          authorization do
            secure :servers do
              creatable_by :@@manager
              destroyable_by :@@administrator
            end

            secure :under_scores do
              updatable_by :@@manager
              column [:name], :updatable_by => :@@administrator
            end
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        without_authorization do
          @secured_server = Server.create
          @secured_under_score = UnderScore.create

          @role_less_user = User.create
          @server_manager_user = User.create
          @server_admin_user = User.create
          @under_score_manager_user = User.create
          @under_score_admin_user = User.create

          server_manager_role = AuthorizationRole.create(
            :securable_type => 'Server', :name => '@@manager')
          server_admin_role = AuthorizationRole.create(
            :securable_type => 'Server', :name => '@@administrator')
          under_score_manager_role = AuthorizationRole.create(
            :securable_type => 'UnderScore', :name => '@@manager')
          under_score_admin_role = AuthorizationRole.create(
            :securable_type => 'UnderScore', :name => '@@administrator')

          AuthorizationGrant.create(
            :authorization_role => server_manager_role,
            :grantee => @server_manager_user)
          AuthorizationGrant.create(
            :authorization_role => server_admin_role,
            :grantee => @server_admin_user)
          AuthorizationGrant.create(
            :authorization_role => under_score_manager_role,
            :grantee => @under_score_manager_user)
          AuthorizationGrant.create(
            :authorization_role => under_score_admin_role,
            :grantee => @under_score_admin_user)
        end
      end

      should 'not permit anonymous user to create server' do
        User.current = nil
        assert_raise Authorization::SecurityError do
          Server.create
        end
      end

      should 'not permit anonymous user to update under_score' do
        User.current = nil
        assert_raise Authorization::SecurityError do
          @secured_under_score.name = 'a name'
          @secured_under_score.save
        end
      end

      should 'not permit anonymous user to delete server' do
        User.current = nil
        assert_raise Authorization::SecurityError do
          @secured_server.destroy
        end
      end

      should 'not permit role-less user to create server' do
        User.current = @role_less_user
        assert_raise Authorization::SecurityError do
          Server.create
        end
      end

      should 'not permit role-less user to update under_score' do
        User.current = @role_less_user
        assert_raise Authorization::SecurityError do
          @secured_under_score.name = 'a name'
          @secured_under_score.save
        end
      end

      should 'not permit role-less user to delete server' do
        User.current = @role_less_user
        assert_raise Authorization::SecurityError do
          @secured_server.destroy
        end
      end

      should 'permit server manager to create servers' do
        User.current = @server_manager_user
        assert_nothing_raised do
          Server.create
        end
      end

      should 'not permit server manager to update servers' do
        User.current = @server_manager_user
        assert_raise Authorization::SecurityError do
          @secured_server.name = 'a name'
          @secured_server.save
        end
      end

      should 'not permit server manager to delete servers' do
        User.current = @server_manager_user
        assert_raise Authorization::SecurityError do
          @secured_server.destroy
        end
      end

      should 'not permit server administrator to create servers' do
        User.current = @server_admin_user
        assert_raise Authorization::SecurityError do
          Server.create
        end
      end

      should 'not permit server administrator to update servers' do
        User.current = @server_admin_user
        assert_raise Authorization::SecurityError do
          @secured_server.name = 'a name'
          @secured_server.save
        end
      end

      should 'permit server administrator to delete servers' do
        User.current = @server_admin_user
        assert_nothing_raised do
          @secured_server.destroy
        end
      end

      should 'not permit server manager to modify under_scores' do
        User.current = @server_manager_user
        assert_raise Authorization::SecurityError do
          @secured_under_score.name = 'a name'
          @secured_under_score.save
        end
      end

      should 'not permit server administrator to modify under_score names' do
        User.current = @server_admin_user
        assert_raise Authorization::SecurityError do
          @secured_under_score.name = 'a name'
          @secured_under_score.save
        end
      end

      should 'not permit under_score manager to create servers' do
        User.current = @under_score_manager_user
        assert_raise Authorization::SecurityError do
          Server.create
        end
      end

      should 'not permit under_score administrator to delete servers' do
        User.current = @under_score_admin_user
        assert_raise Authorization::SecurityError do
          @secured_server.destroy
        end
      end

      should 'permit under_score managers to modify all cols on under_scores' do
        User.current = @under_score_manager_user
        assert_nothing_raised do
          @secured_under_score.name = 'a name'
          @secured_under_score.locked = 'locked'
          @secured_under_score.save
        end
      end

      should 'not permit under_score manager to create under_scores' do
        User.current = @under_score_manager_user
        assert_raise Authorization::SecurityError do
          UnderScore.create
        end
      end

      should 'permit under_score administrator to modify name on under_score' do
        User.current = @under_score_admin_user
        assert_nothing_raised do
          @secured_under_score.name = 'a name'
          @secured_under_score.save
        end
      end

      should 'not permit under_score admin to modify locked on under_score' do
        User.current = @under_score_admin_user
        assert_raise Authorization::SecurityError do
          @secured_under_score.locked = 'locked'
          @secured_under_score.save
        end
      end

    end

    context 'a configuration granting permission to add/remove resources' do
      setup do
        input = %{
          authorization do
            secure :servers do
              resource [:user], :addable_by => :@@manager
              resource [:user], :removable_by => :@@administrator
            end
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        without_authorization do
          @manager_user = User.create
          @admin_user = User.create
          @super_user = User.create

          manager_role = AuthorizationRole.create(:name => '@@manager',
                                                  :securable_type => 'Server')
          admin_role = AuthorizationRole.create(:name => '@@administrator',
                                                :securable_type => 'Server')

          AuthorizationGrant.create(:grantee => @manager_user,
                                    :authorization_role => manager_role)
          AuthorizationGrant.create(:grantee => @admin_user,
                                    :authorization_role => admin_role)
          AuthorizationGrant.create(:grantee => @super_user,
                                    :authorization_role => manager_role)
          AuthorizationGrant.create(:grantee => @super_user,
                                    :authorization_role => admin_role)

          @secured_ownership = Ownership.create
        end
      end

      should 'permit managers to create ownerships' do
        User.current = @manager_user
        assert_nothing_raised do
          Ownership.create(:user_id => 0, :server_id => 1)
        end
      end

      should 'not permit managers to destroy ownerships' do
        User.current = @manager_user
        assert_raise Authorization::SecurityError do
          @secured_ownership.destroy
        end
      end

      should 'not permit administrators to create ownerships' do
        User.current = @admin_user
        assert_raise Authorization::SecurityError do
          Ownership.create(:user_id => 0, :server_id => 1)
        end
      end

      should 'permit administrators to destroy ownerships' do
        User.current = @admin_user
        assert_nothing_raised do
          @secured_ownership.destroy
        end
      end

      should 'permit superusers to create and destroy ownerships' do
        User.current = @super_user
        assert_nothing_raised do
          @new_ownership = Ownership.create
          @new_ownership.destroy
        end
      end

    end

    context 'the use of the :all role' do
      setup do
        input = %{
          authorization do
            secure :servers do
              creatable_by [:all, :@@manager]
            end
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        without_authorization do
          @user_without_roles = User.create
          @user_with_roles = User.create
          @role = AuthorizationRole.create(:securable_type => 'Server',
                                           :name => '@@manager')
          AuthorizationGrant.create(:grantee => @user_with_roles,
                                    :authorization_role => @role)
        end
      end

      should 'let user without roles create servers' do
        User.current = @user_without_roles
        assert_nothing_raised do
          Server.create
        end
      end

      should 'let user with roles create servers' do
        User.current = @user_with_roles
        assert_nothing_raised do
          Server.create
        end
      end

      should 'not let nil current user create servers' do
        User.current = nil
        assert_raise Authorization::SecurityError do
          Server.create
        end
      end
    end

  end
end
