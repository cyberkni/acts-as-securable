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

# Features tested in this test suite:
# All columns on ActiveRecord. This is simply concatenated onto the list
# of every class, instead of having to do multiple levels of checks
# Enforce: column names can't be redefined

# the All keyword symbol for authorization roles, namely, it is special.

# Conditions: created_at is only modifiable when a record is new

# :condition => , # :associated =>

# TODO(bdon): !!!!forget to mix in acts as protected

class Server < ActiveRecord::Base
  acts_as_protected
  has_many :ownerships
  has_many :users, :through => :ownerships
end

class UniversalRuleTest < ActiveSupport::TestCase

  context 'Authorizations of records in general' do

    setup do
      input = %{
        authorization do
          column [:name], :updatable_by => :all
          secure :servers do
          end
        end
      }
      ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
      without_authorization do
        @server = Server.create(:name => 'name')
        @manager_user = User.create

        @manager_role = AuthorizationRole.create(:securable_type => 'Server',
                                                 :name => 'manager')
        AuthorizationGrant.create(:grantee => @manager_user,
                                  :authorization_role => @manager_role)
      end
    end

    teardown do
      delete_all_records
    end

    should 'allow manager to update both locked and name' do
      User.current = @manager_user
      assert_nothing_raised do
        @server.name = 'a new name'
        @server.save!
      end
    end

    should 'respect always keyword on zones'

  end

  # TODO(bdon): only global roles in global column rules?

  context 'global column rules, even without secure blocks' do

    setup do
      input = %{
        authorization do
          column [:name], :updatable_by => :all
        end
      }
      without_authorization do
        @server = Server.create(:name => 'name')
      end

      ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
      without_authorization do
        @server = Server.create(:name => 'name')
      end
    end

    should 'let user without roles update name' do
      User.current = User.create
      assert_nothing_raised do
        @server.name = 'something else'
        @server.save
      end
    end
  end

end