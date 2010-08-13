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

# authorization do
#   secure :servers, :unless => :exclusive do
#     exclusive_role :managers
#     creatable_by :managers, :administrators
#   end
# end
#
# #If the role manager applies to an instance of server,
# #then no other roles apply

require 'test_helper'

class Server < ActiveRecord::Base
  acts_as_protected
end

class ExclusiveRoleTest < ActiveSupport::TestCase

  context 'In exclusive authorizations,' do

    teardown do
      delete_all_records
    end

    context 'when there is a single exclusive authorization,' do

      setup do
        input = %{
          authorization do
            secure :servers do
              exclusive_role :@lockdown_manager
              updatable_by [:@@manager, :@lockdown_manager]
            end
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        without_authorization do
          @open_server = Server.create(:name => 'harry')
          @lockdown_server = Server.create(:name => 'sally')

          @normal_user = User.create
          @special_user = User.create


          @manager_role = AuthorizationRole.create(:securable_type => 'Server',
                                                   :name => '@@manager')

          @ld_role = AuthorizationRole.create(:securable => @lockdown_server,
                                                   :name => '@lockdown_manager')

          AuthorizationGrant.create(:grantee => @normal_user,
                                    :authorization_role => @manager_role)

          AuthorizationGrant.create(:grantee => @special_user,
                                    :authorization_role => @ld_role)

          AuthorizationGrant.create(:grantee => @special_user,
                                    :authorization_role => @manager_role)
        end
      end

      should 'allow normal user to update open server' do
        User.current = @normal_user
        assert_nothing_raised do
          @open_server.name = 'betty'
          @open_server.save
        end
      end

      should 'not allow normal user to update lockdown server' do
        User.current = @normal_user
        assert_raise Authorization::SecurityError do
          @lockdown_server.name = 'betty'
          @lockdown_server.save
        end
      end

      should 'allow special user to update open server' do
        User.current = @special_user
        assert_nothing_raised do
          @open_server.name = 'betty'
          @open_server.save
        end
      end

      should 'allow special user to update lockdown server' do
        User.current = @special_user
        assert_nothing_raised do
          @lockdown_server.name = 'betty'
          @lockdown_server.save
        end
      end
    end

    context 'when there is multiple exclusive authorizations,' do

      setup do
        input = %{
          authorization do
            secure :servers do
              exclusive_role :@lockdown_manager_1
              exclusive_role :@lockdown_manager_2
              updatable_by [:@@manager, :@lockdown_manager_1,
                                      :@lockdown_manager_2]
            end
          end
        }
        ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
        without_authorization do
          @open_server = Server.create(:name => 'harry')
          @lockdown_server = Server.create(:name => 'sally')

          @normal_user = User.create
          @special_user = User.create

          @manager_role = AuthorizationRole.create(:securable_type => 'Server',
                                                   :name => '@@manager')
          @special_role_1 = AuthorizationRole.create(
                              :securable => @lockdown_server,
                              :name => '@lockdown_manager_1')
          @special_role_2 = AuthorizationRole.create(
                              :securable => @lockdown_server,
                              :name => '@lockdown_manager_2')
          AuthorizationGrant.create(:grantee => @normal_user,
                                    :authorization_role => @manager_role)
          AuthorizationGrant.create(:grantee => @special_user,
                                    :authorization_role => @special_role_1)
          AuthorizationGrant.create(:grantee => @special_user,
                                    :authorization_role => @special_role_2)
          AuthorizationGrant.create(:grantee => @special_user,
                                    :authorization_role => @manager_role)
        end
      end

      should 'allow normal user to update open server' do
        User.current = @normal_user
        assert_nothing_raised do
          @open_server.name = 'betty'
          @open_server.save
        end
      end

      should 'not allow normal user to update lockdown server' do
        User.current = @normal_user
        assert_raise Authorization::SecurityError do
          @lockdown_server.name = 'betty'
          @lockdown_server.save
        end
      end

      should 'allow special user to update open server' do
        User.current = @special_user
        assert_nothing_raised do
          @open_server.name = 'betty'
          @open_server.save
        end
      end

      should 'allow special user to update lockdown server' do
        User.current = @special_user
        assert_nothing_raised do
          @lockdown_server.name = 'betty'
          @lockdown_server.save
        end
      end
    end
  end

end
