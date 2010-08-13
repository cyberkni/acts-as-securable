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
end

class UnderScore < ActiveRecord::Base
  acts_as_protected
end

class AuthorizationRoleModelTest < ActiveSupport::TestCase

  context 'in the authorization role model' do

    teardown do
      delete_all_records
    end

    should 'parse signatures correctly' do
      hsh = AuthorizationRole.parse('admin')
      assert_equal '$admin', hsh['name']
      hsh = AuthorizationRole.parse('ServerType:admin')
      assert_equal '@@admin', hsh['name']
      assert_equal 'ServerType', hsh['securable_type']
      hsh = AuthorizationRole.parse('ServerType/dns:admin')
      assert_equal '@admin', hsh['name']
      assert_equal 'ServerType', hsh['securable_type']
      assert_equal 'dns', hsh['securable_name']
      hsh = AuthorizationRole.parse('ServerType/d/ns:admin')
      assert_equal '@admin', hsh['name']
      assert_equal 'ServerType', hsh['securable_type']
      assert_equal 'd/ns', hsh['securable_name']
      hsh = AuthorizationRole.parse('ServerType/d:ns:admin')
      assert_equal '@admin', hsh['name']
      assert_equal 'ServerType', hsh['securable_type']
      assert_equal 'd:ns', hsh['securable_name']
    end

    context 'In valid Authorization Role objects,' do

      context 'formatting of role names' do
        should 'not permit names under 3 characters' do
          assert !AuthorizationRole.new(:name => '$a').valid?
        end

        should 'not permit names over 25 characters' do
          twentysix = '$fourfourfourfourfourfourtw'
          assert !AuthorizationRole.new(:name => twentysix).valid?
        end

        should 'not permit hyphens in role names' do
          assert !AuthorizationRole.new(:name => '@r2-d').valid?
        end

        should 'accept a role name with digits, numbers and underscores' do
          assert AuthorizationRole.new(:name => '$sefljn234_32df').valid?
        end

        should 'be all undercase' do
          assert !AuthorizationRole.new(:name => '$FOO').valid?
        end

      end

      context 'Valid sigils in role names' do

        setup do
          input = %{
            authorization do
            end
          }
          ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
          without_authorization do
            @server = Server.create!
          end
          ActiveRecord::Base.acl_manager.disable!
        end

        should 'allow $ for global role' do
          assert AuthorizationRole.new(:name => '$role').valid?
        end

        should 'not allow @ for global role' do
          role = AuthorizationRole.new(:name => '@role')
          role.valid?
          name_errors = role.errors.on(:name)
          assert name_errors.first.match('Global role name must begin with \$')
        end

        should 'not allow @@ for global role' do
          role = AuthorizationRole.new(:name => '@@role')
          role.valid?
          name_errors = role.errors.on(:name)
          assert name_errors.first.match('Global role name must begin with \$')
        end

        should 'not allow $ for instance role' do
          role = AuthorizationRole.new(:name => '$role',
                                        :securable => @server)
          role.valid?
          name_errors = role.errors.on(:name)
          assert name_errors.first.match('Instance role name must begin with @')
        end

        should 'allow @ for instance role' do
          assert AuthorizationRole.new(:name => '@role',
                                       :securable => @server).valid?
        end

        should 'not allow @@ for instance role' do
          role = AuthorizationRole.new(:name => '@@role',
                                        :securable => @server)
          role.valid?
          name_errors = role.errors.on(:name)
          assert name_errors.first.match('Instance role name must begin with @')
        end

        should 'not allow $ for class role' do
          role = AuthorizationRole.new(:name => '$role',
                                        :securable_type => 'Server')
          role.valid?
          name_errors = role.errors.on(:name)
          assert name_errors.first.match('Class role name must begin with @@')
        end

        should 'not allow @ for class role' do
          role = AuthorizationRole.new(:name => '@role',
                                        :securable_type => 'Server')
          role.valid?
          name_errors = role.errors.on(:name)
          assert name_errors.first.match('Class role name must begin with @@')
        end

        should 'allow @@ for class role' do
          assert AuthorizationRole.new(:name => '@@role',
                                       :securable_type => 'Server').valid?
        end
      end

      context 'valid authorization roles' do
        setup do
          input = %{
            authorization do
            end
          }
          ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
          without_authorization do
            @server = Server.create!(:name => 'sally')
            @another_server = Server.create!(:name => 'harry')
          end
          ActiveRecord::Base.acl_manager.disable!
        end

        # ROLE NAME CONFLICTS

        should 'not permit instance roles with same name on same instance.' do
          AuthorizationRole.create!(:name => '@manager', :securable => @server)
          assert !AuthorizationRole.new(:name => '@manager',
                                           :securable => @server).valid?
        end

        should 'not permit class roles with same name on same class.' do
          AuthorizationRole.create!(:name => '@@manager',
                                   :securable_type => 'Server')
          assert !AuthorizationRole.new(:name => '@@manager',
                                           :securable_type => 'Server').valid?
        end

        should 'not permit global roles with same names' do
          AuthorizationRole.create!(:name => '$manager')
          assert !AuthorizationRole.new(:name => '$manager').valid?
        end

        # VALID ROLE NAMES

        should 'permit instance roles on different objects to share name.' do
          AuthorizationRole.create!(:name => '@manager', :securable => @server)
          assert_nothing_raised do
            AuthorizationRole.create!(:name => '@manager',
                                      :securable => @another_server)
          end
        end

        should 'permit class roles on different classes to share name.' do
          AuthorizationRole.create!(:name => '@@manager',
                                   :securable_type => 'Server')
          assert_nothing_raised do
            AuthorizationRole.create!(:name => '@@manager',
                                      :securable_type => 'UnderScore')
          end
        end
      end

      context 'In the association methods mixed in to the model' do
        setup do
          input =  %{
            authorization do
            end
          }
          ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
          without_authorization do
            @server = Server.create!(:name => 'sally')
          end
          ActiveRecord::Base.acl_manager.disable!
        end

        should 'implement applicable_roles' do
          role = AuthorizationRole.create!(:name => '@@manager',
                                          :securable_type => 'Server')
          assert AuthorizationRole.applicable_to(@server).include?(role)
        end
      end
    end

    context 'in the finder for authorization roles, ' do
      setup do
        without_authorization do
          AuthorizationRole.create!(:name => '@@user',
                                    :securable_type => 'Server')
          @server1 = Server.create!(:name => 'theserver')
          server2 = Server.create!(:name => 'anotherserver')
          AuthorizationRole.create!(:name => '@user', :securable => @server1)
          AuthorizationRole.create!(:name => '@user', :securable => server2)
          AuthorizationRole.create!(:name => '@@user',
                                    :securable_type => 'Unrelated')
        end
      end

      should 'implement retrieving an index' do
        roles = AuthorizationRole.find_by_securable(nil,nil,nil,nil)
        assert_equal 4, roles.size
      end

      should 'implement finding by securable name and type' do
        roles = AuthorizationRole.find_by_securable('theserver', nil, 'Server',
                                                    nil)
        assert_equal 2, roles.size
      end

      should 'implement finding by securable type and id' do
        roles = AuthorizationRole.find_by_securable(nil, @server1.id, 'Server',
                                                    nil)
        assert_equal 2, roles.size
      end

      should 'implement finding by just securable type' do
        roles = AuthorizationRole.find_by_securable(nil, nil, 'Server', nil)
        assert_equal 1, roles.size
      end

      should 'implement finding by role name' do
        roles = AuthorizationRole.find_by_securable(nil, nil, nil, '@user')
        assert_equal 2, roles.size
      end

      should 'implement finding by role name and securable name and type' do
        roles = AuthorizationRole.find_by_securable('theserver', nil,
                                                    'Server', '@user')
        assert_equal 1, roles.size
      end

      should 'implement finding by role name and securable type and id' do
        roles = AuthorizationRole.find_by_securable(nil, @server1.id,
                                                    'Server', '@user')
        assert_equal 1, roles.size
      end

      should 'implement finding by role name and securable type' do
        roles = AuthorizationRole.find_by_securable(nil, nil, 'Server',
                                                    '@@user')
        assert_equal 1, roles.size
      end

    end
  end

end