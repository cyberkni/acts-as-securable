# Copyright:: Copyright 2010 Google Inc.
# License:: All Rights Reserved.
# Original Author:: Brandon Liu (mailto:bdon@google.com)

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
