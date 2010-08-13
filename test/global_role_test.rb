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

# Test global roles

require 'test_helper'

class Server < ActiveRecord::Base
  acts_as_protected
end

class UnderScore < ActiveRecord::Base
  acts_as_protected
end

class GlobalRoleTest < ActiveSupport::TestCase

 context 'Granting roles that apply globally' do

    setup do
      input = %{
        authorization do
          secure :servers do
            creatable_by :$root
          end

          secure :under_scores do
            creatable_by :$root
          end
        end
      }
      ActiveRecord::Base.acl_manager = Authorization::Manager.new(input)
      without_authorization do
        @root_user = User.create
        global_role = AuthorizationRole.create(:name => '$root')
        AuthorizationGrant.create(:authorization_role => global_role,
                                  :grantee => @root_user)
      end
    end

    teardown do
      delete_all_records
    end

    should 'permit admin user to create Servers' do
      User.current = @root_user
      assert_nothing_raised do
        Server.create
      end
    end

    should 'permit admin user to create UnderScores' do
      User.current = @root_user
      assert_nothing_raised do
        UnderScore.create
      end
    end
  end

end