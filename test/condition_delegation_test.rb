# Copyright (C) 2010 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'test_helper'

class Server < ActiveRecord::Base
  acts_as_protected
  has_one :server_item, :dependent => :destroy
  def parent
    nil
  end
end

class ServerItem < ActiveRecord::Base
  acts_as_protected
  belongs_to :server

  def root_users
    [User.first]
  end

  has_one :server_item_item

end

class ServerItemItem < ActiveRecord::Base
  acts_as_protected
  belongs_to :server_item
end

class ConditionDelegationTest < ActiveSupport::TestCase
  context 'In rules that specify conditions on the user or object,' do

    teardown do
      delete_all_records
    end

    context 'delegation test' do
      setup do
        input = %{
          authorization do
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        without_authorization do
          @normal_user = User.create
          @server = Server.create
          @server_item = ServerItem.create(:server => @server)
          @role_manager = AuthorizationRole.create(:securable => @server_item,
                                                   :name => '@manager')
          AuthorizationGrant.create(:authorization_role => @role_manager,
                                    :grantee => @normal_user)
        end
      end

      teardown do
        delete_all_records
      end

      should 'allow a user to create server, delegating to another object' do
        input = %{
          authorization do
            secure :servers do
              updatable_by :@manager, :of_associated => :server_item
            end
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        User.current = @normal_user
        assert_nothing_raised do
          @server.name = 'something else'
          @server.save
        end
      end

      should 'allow user to update server, delegating through two objects' do
        without_authorization do
          @serveritemitem = ServerItemItem.create(:server_item => @server_item)
          @role_op = AuthorizationRole.create(:securable => @serveritemitem,
                                              :name => '@operator')
          AuthorizationGrant.create(:authorization_role => @role_op,
                                    :grantee => @normal_user)
        end

        input = %{
          authorization do
            secure :servers do
              updatable_by :@operator, :of_associated => {:server_item =>
                                                         :server_item_item}
            end
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        User.current = @normal_user
        assert_nothing_raised do
          @server.name = 'something else'
          @server.save
        end
      end

      should 'not blow up on nil attributes, instead deny authorization' do
        input = %{
          authorization do
            secure :servers do
              updatable_by :@operator, :of_associated => {:server_item =>
                                                         :server_item_item}
            end
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        User.current = @normal_user
        assert_raise Authorization::SecurityError do
          @server.name = 'something else'
          @server.save
        end
      end

      should 'throw nomethoderror on missing methods' do
        input = %{
          authorization do
            secure :servers do
              updatable_by :@manager, :of_associated => :baz
            end
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        User.current = @normal_user
        assert_raise NoMethodError do
          @server.name = 'something else'
          @server.save
        end
      end

    end

    context 'In destroy operations where there is dependent objects being
             destroyed' do
      setup do
        input = %{
          authorization do
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        without_authorization do
          @normal_user = User.create
          @server = Server.create
          @server_item = ServerItem.create(:server => @server)

          @role_manager = AuthorizationRole.create(:securable_type => 'Server',
                                                   :name => '@@manager')
          AuthorizationGrant.create(:authorization_role => @role_manager,
                                    :grantee => @normal_user)
        end
      end

      should 'allow a user to destroy ServerItems while destroying a Server' do
        input = %{
          authorization do
            secure :servers do
              destroyable_by :@@manager
            end

            secure :server_items do
              destroyable_if_destroying_associated :server
            end
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        assert Server.find(:all).size == 1
        User.current = @normal_user
        assert_nothing_raised do
          @server.destroy
        end
        assert Server.find(:all).size == 0
        assert ActiveRecord::Base.acl_manager.destroy_pool.empty?
      end

      should 'allow a user to destroy ServerItems when destroying nested obj' do
        input = %{
          authorization do
            secure :servers do
              destroyable_by :@@manager
            end

            secure :server_items do
              destroyable_if_destroying_associated :clone => :server
            end
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        assert Server.find(:all).size == 1
        User.current = @normal_user
        assert_nothing_raised do
          @server.destroy
        end
        assert Server.find(:all).size == 0
        assert ActiveRecord::Base.acl_manager.destroy_pool.empty?
      end

      should 'allow a user to destroy ServerItems if there is explicit
              authorization given' do
        input = %{
          authorization do
            secure :servers do
              destroyable_by :@@manager
            end

            secure :server_items do
              destroyable_by :@@manager, :of_associated => :server
            end
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        assert Server.find(:all).size == 1
        User.current = @normal_user
        assert_nothing_raised do
          @server.destroy
        end
        assert Server.find(:all).size == 0
        assert ActiveRecord::Base.acl_manager.destroy_pool.empty?
      end

      should 'not allow a Server destroy operation if no authorization
              is given to destroy associated ServerItem' do
        input = %{
          authorization do
            secure :servers do
              destroyable_by :@@manager
            end
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        assert Server.find(:all).size == 1
        User.current = @normal_user
        assert_raise Authorization::SecurityError do
          @server.destroy
        end
        assert Server.find(:all).size == 1
        assert ActiveRecord::Base.acl_manager.destroy_pool.empty?
      end

    end

    context "In rules that query for the current user's membership" do
      setup do
        without_authorization do
          @normal_user = User.create
          @server = Server.create
          @server_item = ServerItem.create(:server => @server)
          @role_manager = AuthorizationRole.create(:securable_type => 'Server',
                                                   :name => '@@manager')
          AuthorizationGrant.create(:authorization_role => @role_manager,
                                    :grantee => @normal_user)
        end
      end

      should 'correctly check an associated group for membership.' do
        User.current = @normal_user
        input = %{
          authorization do
            secure :servers do
              updatable_by :@@manager,
                :if_user_in_associated => {:server_item => :root_users}
            end
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        assert_nothing_raised do
          @server.name = 'something else'
          @server.save
        end
      end

      should 'throw NoMethodError on undefined groups.' do
        input = %{
          authorization do
            secure :servers do
              updatable_by :@@manager,
                :if_user_in_associated => {:server_item => :nonexistents}
            end
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        User.current = @normal_user
        assert_raise NoMethodError do
          @server.name = 'something else'
          @server.save
        end
      end

    end

    context "In rules that query for the current user's membership" do
      setup do
        without_authorization do
          @normal_user = User.create
          @server = Server.create
          @server_item = ServerItem.create(:server => @server)
          @role_manager = AuthorizationRole.create(:securable_type => 'Server',
                                                   :name => '@@manager')
          AuthorizationGrant.create(:authorization_role => @role_manager,
                                    :grantee => @normal_user)
        end
      end

      should 'correctly check for nil.' do
        User.current = @normal_user
        input = %{
          authorization do
            secure :servers do
              updatable_by :@@manager, :if_no => :parent
            end
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        assert_nothing_raised do
          @server.name = 'something else'
          @server.save
        end
      end

    end
  end
end
