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

# test the ACL query system for roles on specific instances

require 'test_helper'

class Server < ActiveRecord::Base
  acts_as_protected
  has_many :ownerships
  has_many :users, :through => :ownerships
end

class InstanceRoleTest < ActiveSupport::TestCase

 context 'Granting roles that apply to specific instances of securables' do

    setup do
      input = %{
        authorization do
          secure :servers do
            updatable_by [:@@manager, :@instance_manager]
          end
        end
      }
      ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
      without_authorization do
        @secured_server_one = Server.create
        @secured_server_two = Server.create
        @instance_manager_user = User.create
        @class_manager_user = User.create

        instance_role = AuthorizationRole.create(
                                           :securable => @secured_server_one,
                                           :name => '@instance_manager')
        class_role = AuthorizationRole.create(:securable_type => 'Server',
                                              :name => '@@manager')
        AuthorizationGrant.create(:authorization_role => instance_role,
                                  :grantee => @instance_manager_user)
        AuthorizationGrant.create(:authorization_role => class_role,
                                  :grantee => @class_manager_user)
      end
    end

    teardown do
      delete_all_records
    end

    should 'permit instance manager to update server one' do
      User.current = @instance_manager_user
      assert_nothing_raised do
        @secured_server_one.name = 'a name'
        @secured_server_one.save
      end
    end

    should 'not permit instance manager to update server two' do
      User.current = @instance_manager_user
      assert_raise Authorization::SecurityError do
        @secured_server_two.name = 'a name'
        @secured_server_two.save
      end
    end

    should 'permit class manager to update server one and two' do
      User.current = @class_manager_user
      assert_nothing_raised do
        @secured_server_one.name = 'a name'
        @secured_server_one.save
        @secured_server_two.name = 'a name'
        @secured_server_two.save
      end
    end

  end

end
