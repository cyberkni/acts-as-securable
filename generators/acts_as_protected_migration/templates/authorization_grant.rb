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

class AuthorizationGrant < ActiveRecord::Base

  acts_as_protected

  validates_presence_of :grantee_id, :grantee_type,
                        :message => 'must be a valid user or group'
  validates_presence_of :authorization_role_id
  validates_uniqueness_of :authorization_role_id,
                          :scope => [:grantee_id, :grantee_type],
                          :message => 'cannot grant same role'

  belongs_to :authorization_role
  belongs_to :grantee, :polymorphic => true

  def to_s
    "Granted #{authorization_role} to #{grantee_type} #{grantee_id}"
  end

  # Serialization helpers

  def grantee_name
    grantee.name
  end

  def authorization_role_to_s
    authorization_role.to_s
  end

  def to_xml(opts={})
    methods = Array(opts[:methods]) | [:grantee_name, :authorization_role_to_s]
    super(opts.merge(:methods => methods))
  end

end
