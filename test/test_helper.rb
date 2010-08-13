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

require 'rubygems'
require 'active_support'
require 'active_record'
require 'active_support/test_case'
require 'flexmock/test_unit'
# TODO(bdon): In production, comment this out
# require File.join(File.dirname(__FILE__), %w{.. .. .. gems
# thoughtbot-shoulda-2.10.2 lib shoulda})
# TODO(bdon): require the gem on development workstation
require 'shoulda'
require File.join(File.dirname(__FILE__), %w{.. lib reader})
require File.join(File.dirname(__FILE__), %w{.. lib acts_as_protected})
require File.join(File.dirname(__FILE__), %w{.. lib in_model})
require File.join(File.dirname(__FILE__), %w{.. generators
    acts_as_protected_migration templates authorization_grant})
require File.join(File.dirname(__FILE__), %w{.. generators
    acts_as_protected_migration templates authorization_role})
include Authorization

# setup of schema

require 'active_record'

options = {:adapter => 'sqlite3', :timeout => 500, :database => ':memory:'}
ActiveRecord::Base.establish_connection(options)
ActiveRecord::Base.configurations = {'sqlite3_ar_integration' => options}
ActiveRecord::Base.connection
ActiveRecord::Migration.verbose = false

load(File.join(File.dirname(__FILE__), 'schema.rb'))

# Development helpers

def log_to(stream)
  old_logger = ActiveRecord::Base.connection.instance_variable_get(:@logger)
  ActiveRecord::Base.connection.instance_variable_set(:@logger,
                                                      Logger.new(stream))
  yield
  ActiveRecord::Base.connection.instance_variable_set(:@logger, old_logger)
end

def stub_user_with_roles(*roles)
  temp = []
  roles.each do |r|
    temp << flexmock(:name => r, :securable_type => 'Server',
                     :securable_id => nil)
  end
  flexmock(:authorization_roles => temp, :id => 1)
end
alias stub_user_with_role stub_user_with_roles

def stub_user_without_roles
  flexmock(:authorization_roles => [], :id => 1)
end

# Generalized user class

class User < ActiveRecord::Base
  cattr_accessor :current
  has_many :ownerships
  has_many :servers, :through => :ownerships
  acts_as_grantee

  def authoritative_group_ids
    []
  end
end

def assert_error_message_includes(*args)
  satisfied = args.inject(true) do |result, token|
    result && $!.message.include?(token)
  end
  assert satisfied
end

def delete_all_records
  ActiveRecord::Base.send(:subclasses).each do |klass|
    klass.delete_all
  end
end