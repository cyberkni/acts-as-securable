# Copyright:: Copyright 2010 Google Inc.
# License:: All Rights Reserved.
# Original Author:: Brandon Liu (mailto:bdon@google.com)

class AuthorizationRoleError < StandardError
end

class AuthorizationRole < ActiveRecord::Base

  acts_as_protected

  # Return the authorization roles applicable to an object.
  #
  # Args:
  # - object - the object being acted upon
  #
  # returns:
  # - collection of AuthorizationRoles that are scoped on the object, including
  #   global and class roles.
  named_scope :applicable_to, lambda { |object|
      {:conditions => ["(
        (securable_id = 0 AND securable_type = '')
        OR
        (securable_id = 0 OR securable_id = ?)
        AND
        (securable_type = ? OR securable_type = ?)
      )", (object.new_record? ? 0 : object.id), object.class.to_s,
           object.class.base_class.to_s]}
    }

  named_scope :applicable_to_class, lambda { |obj_class|
    {:conditions => ["(
      (securable_id = 0 AND securable_type = '')
      OR
      (securable_id = 0)
      AND
      (securable_type = ? OR securable_type = ?)
    )", obj_class.to_s, obj_class.base_class.to_s]}
  }

  named_scope :held_by, lambda { |user|
    {:conditions => [
      " authorization_roles.id IN (
        SELECT authorization_roles.id FROM authorization_roles
        INNER JOIN authorization_grants ON authorization_roles.id =
        authorization_role_id WHERE
        (grantee_type = 'User' AND grantee_id = ?)
        OR
        (grantee_type = 'Group' and grantee_id in
          (?)
        )
      )", user.id, user.authoritative_group_ids.to_a.map(&:to_i)
      ]}
  }

  named_scope :named, lambda {|name|
    {:conditions => ["name = ?", name.to_s]}
    }

  EMPTY_ID = 0 unless defined? EMPTY_ID
  EMPTY_TYPE = '' unless defined? EMPTY_TYPE

  # An identifier used for serialization.
  # returns:
  #  - useful string representation of identifier
  #
  def securable_identifier
     if instance_role?
       if securable
         securable.to_s
       end
     elsif class_role?
       'ALL'
     else
       nil
     end
   end

   def to_xml(opts={})
     methods = Array(opts[:methods]) | [:securable_identifier]
     super(opts.merge(:methods => methods))
   end

  def securable_id
    self[:securable_id] || EMPTY_ID
  end

  def securable_type
    self[:securable_type] || EMPTY_TYPE
  end

  def global_role?
    securable_id == EMPTY_ID && securable_type == EMPTY_TYPE
  end

  def class_role?
    securable_id == EMPTY_ID && securable_type != EMPTY_TYPE
  end

  def instance_role?
    securable_id != EMPTY_ID
  end

  belongs_to :securable, :polymorphic => true
  has_many :authorization_grants

  validates_presence_of :name

  # Uniqueness is reinforced with regards to concurrency by db index
  # Need to wrap saves in checker for ActiveRecord::StatementInvalid
  validates_uniqueness_of :name, :scope => [:securable_type, :securable_id]

  validates_length_of :name, :within => 3..25
  validates_format_of :name, :with => /^[a-z0-9_@$]*$/,
                      :message => 'Invalid characters in role name'
  validate :validate_sigils

  def validate_sigils
    if global_role?
      unless name.match /^\$/
        errors.add :name, 'Global role name must begin with $'
      end
    elsif class_role?
      unless name.match /^@@/
        errors.add :name, 'Class role name must begin with @@'
      end
    else
      unless name.match /^@[^@]/
        errors.add :name, 'Instance role name must begin with @'
      end
    end
  end

  def to_s
    if global_role?
      "GLOBAL ROLE #{name}"
    elsif class_role?
      "CLASS ROLE #{name} on all #{securable_type.pluralize}"
    else
      "INSTANCE ROLE #{name} on instance #{securable_id} of
       #{securable_type.pluralize}"
    end
  end

  # Parse an AuthorizationRole signature into its parts
  # Args:
  #  -signature identifying a role
  # Returns:
  #  - Hash of name, securable_type, securable_name
  #
  def self.parse(token)
    result = {}
    return result unless token
    colon = token.rindex(':')
    slash = token.index('/')

    if colon.nil? and slash.nil?
      result['name'] = "$#{token}"
    elsif slash.nil?
      result['securable_type'] = token[0..colon-1]
      result['name'] = "@@#{token[colon+1..-1]}"
    else
      result['securable_name'] = token[slash+1..colon-1]
      result['securable_type'] = token[0..slash-1]
      result['name'] = "@#{token[colon+1..-1]}"
    end
    return result
  end

  # Find a AuthorizationRole by it's signature which is
  # ROLE_NAME for global roles
  # SECURABLE_TYPE:ROLE_NAME for class roles
  # SECURABLE_TYPE/SECURABLE_ID:ROLE_NAME for instance roles
  #
  # Args:
  #  - signature: signature that identifies an authorization role
  #
  def self.find_by_signature(signature)
    parsed = self.parse(signature)
    self.find_by_securable(parsed['securable_name'], nil,
                           parsed['securable_type'], parsed['name'])
  end

  # Find an authorization role by its securable_type and securable_name
  # parameters.
  #
  # args:
  # - securable_name: optional, but must specify securable_type
  #     the name of the securable.
  # - securable_id: the ID of the securable.
  # - securable_type: the class of the securable (string).
  #     if this is not present,
  #     all roles will be returned.
  # - name: the name of the role. This is composed with any of the above options
  #
  # returns:
  #   a collection of AuthorizationRoles.
  #
  def self.find_by_securable(securable_name, securable_id, securable_type, name)
    #the type and the securable name
    if securable_name && securable_type
      object = securable_type.constantize.find_by_name(securable_name)
      return [] if object.nil?
      result = AuthorizationRole.applicable_to(object)
    #the type and the id
    elsif securable_type && securable_id
      object = securable_type.constantize.find_by_id(securable_id)
      return [] if object.nil?
      result = AuthorizationRole.applicable_to(object)
    #just the type
    elsif securable_type && securable_id.nil?
      result = AuthorizationRole.applicable_to_class(
          securable_type.constantize)
    #nothing, retrieve all
    else
      result = AuthorizationRole
    end

    if name
      return result.find(:all, :conditions => {:name => name})
    else
      return result.find(:all)
    end
  end

end