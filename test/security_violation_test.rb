require 'test_helper'

class Server < ActiveRecord::Base
  acts_as_protected
end

class User < ActiveRecord::Base
  def to_s
    return name
  end
end

class SecurityViolationtest < ActiveSupport::TestCase


  context 'When displaying a security violation,' do
    setup do
      input = %{
        authorization do
          secure :servers do
            column [:name, :locked], :updatable_by => :$foo
            column [:locked], :updatable_by => :bar
            column [:name], :updatable_by => :baz
          end
        end
      }
      ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
      without_authorization do
        @user = User.create
        @server = Server.create
        @foo = AuthorizationRole.create(:name => '$foo')
        @anotheruser = User.create(:name => 'anotheruser')
        @role_less_user = User.create
        role = AuthorizationRole.create(:name => '@@arole',
                                        :securable_type => 'server')
        AuthorizationGrant.create(:authorization_role => role,
                                  :grantee => @user)
        AuthorizationGrant.create(:authorization_role => @foo,
                                  :grantee => @anotheruser)
      end
    end

    teardown do
      delete_all_records
    end

    context 'and displaying the roles held by the user' do
      should 'show the role that the user holds' do
        User.current = @user
        begin
          Server.create
        rescue Authorization::SecurityError
          assert_error_message_includes('arole')
        end
      end

      should 'tell when there is no current user' do
        User.current = nil
        begin
          Server.create
        rescue Authorization::SecurityError
          assert_error_message_includes('Not logged in')
        end
      end

      should 'show that the user holds no roles' do
        User.current = @role_less_user
        begin
          Server.create
        rescue Authorization::SecurityError
          assert_error_message_includes('no roles')
        end
      end

    end

    context 'and displaying the authorized roles and the grantees' do
      should 'show that role foo can update and is held by anotheruser' do
        User.current = @user
        begin
          @server.name = 'something else'
          @server.save
        rescue Authorization::SecurityError
          assert_error_message_includes('foo', 'anotheruser')
        end
      end
      should 'show that role baz can update but does not exist in database'

    end

    context 'and displaying the prohibited action' do
      setup do
         User.current = @user
       end

      should 'tell the user the Class of the object' do
        @server.name = 'sally'
        begin
          @server.save
        rescue Authorization::SecurityError
          assert_error_message_includes('Server')
        end
      end

      should 'tell the user the ID of the object on update' do
        @server.name = 'sally'
        begin
          @server.save
        rescue Authorization::SecurityError
          assert_error_message_includes(@server.id.to_s)
        end
      end

      should 'not display an ID on a create action'
      should 'Display the original action that triggered the prohibited action'

      should 'display that a create action was prohibited' do
        begin
          Server.create
        rescue Authorization::SecurityError
          assert_error_message_includes('create')
        end
      end

      should 'display that a destroy action was prohibited' do
        begin
          @server.destroy
        rescue Authorization::SecurityError
          assert_error_message_includes('delete')
        end
      end

      should 'display that an update action was prohibited on all columns' do
          @server.name = 'sally'
          @server.locked = false
        begin
          @server.save
        rescue Authorization::SecurityError
          assert_error_message_includes('name', 'locked')
        end
      end
      should 'display that an update action was prohibited on some columns'
      should 'display that an add resource action was prohibited'
      should 'display that a remove resource action was prohibited'
    end

    should 'show OVERRIDE'
    should 'show universal rules in ACL printout'

  end
end