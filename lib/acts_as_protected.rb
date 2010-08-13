# Copyright:: Copyright 2010 Google Inc.
# License:: All Rights Reserved.
# Original Author:: Brandon Liu (mailto:bdon@google.com)

require File.dirname(__FILE__) + '/helper'
require 'singleton'
require 'active_record'

module Authorization
  # Superclass for all exceptions thrown by the plugin.
  class AuthorizationError < StandardError
  end

  class ActionNotSupportedError < AuthorizationError
  end

  # Temporarily disable authorization checks.
  def without_authorization
    unless ActiveRecord::Base.acl_manager
      raise SecurityError, 'no manager loaded'
    end
    ActiveRecord::Base.acl_manager.disable!
    yield
    ActiveRecord::Base.acl_manager.enable!
  end

  # The ACL manager holds the configuration of the system.
  # It is queried for authorization requests.
  class Manager

    # When reading the class definition of Manager, add attribute to Base
    ActiveRecord::Base.class_eval do
      cattr_accessor :acl_manager
    end

    # remove this later for security
    attr_reader :rules
    attr_accessor :destroy_pool, :initial_destroy

    def disable!
      @logger.warn 'ACL Manager is disabled - skipping authorization checks.'
      @disabled = true
    end

    def enable!
      @logger.warn 'ACL Manager is enabled.'
      @disabled = false
    end

    # Create a new ACL manager.
    #
    # Args:
    # input - an input string or file
    #
    # Returns:
    # - an inititalized Authorization::Manager
    def initialize(input)
      if defined? Rails
        @logger = Rails.logger
      else
        @logger = Logger.new($stdout)
      end
      reader = Reader.new
      reader.parse(input)
      @rules = reader.resources.dup
      @universal_creators = reader.universal_creators.dup
      @universal_updaters = reader.universal_updaters.dup
      @universal_deleters = reader.universal_deleters.dup

      # Keeps track of all the objects being destroyed in a transaction.
      @destroy_pool = []
      @initial_destroy = nil
      @disabled = false

      return true

    end

    # TODO(bdon): refactor this method
    # Raise a security error, called from a model's installed callback when
    # an action is not permitted.
    # Should display:
    #   The object and action being attempted
    #   The current user
    #   The roles scoped on the object the user holds
    #   The roles authorized to do the action
    #   Who holds the authorized roles
    #
    # args:
    #  - the action, one of create, update, delete (more coming)
    #  - the object (with object.changed being its changed attributes)
    #
    # raises:
    #  - a SecurityError, with a message describing the current user's
    #    held roles, and the roles/grantees that are authorized to perform
    #    the action.
    def security_error(action, object)
      def object_with_id(object)
        if object.id.nil?
          return "a new #{object.class}"
        else
          changed = object.changed
          if changed.empty?
           return "#{object.class}[#{object.id}]"
         else
           return "#{object.class}[#{object.id}] on columns
                   [#{changed.join(", ")}]"
         end
        end
      end

      # TODO(bdon): scope on object
      def held_roles(user)
        if user
          held_roles = AuthorizationRole.held_by(user)
          if held_roles.empty?
            return "Current user #{user} holds no roles."
          else
            return "Current user #{user} holds roles:\n
                    #{held_roles.join("\n")}"
          end
        else
          return 'Not logged in: no roles held.'
        end
      end

      def class_roles(action, object)
        class_rule = rules[object.class.to_s.tableize.to_sym]
        roles_permitted = roles_permitted_to(action, class_rule, object,
                                             object.changed)
        return 'No roles can perform this action.' if roles_permitted.empty?
        result = ''
        roles_permitted.each do |permitted_role_name, options|
          role = AuthorizationRole.applicable_to(object).find_by_name(
              permitted_role_name.to_s)
          next if role.nil?
          result << "#{role} can perform this action, and is held by:\n"
          g = role.authorization_grants
          result << g.map{ |g| "#{g.grantee_type} #{g.grantee}" }.join("\n")
          result << "\n"
        end
        return result
      end

      message = "\n"
      message << "Not permitted to #{action} #{object_with_id(object)}.\n"
      message << held_roles(User.current) << "\n"
      message << class_roles(action, object) << "\n"
      message << 'Please refer to authorizations.rb for role authorizations.'
      message << "\n\n"

      # If the destroy transaction fails, this is one exit point.
      # the other exit point is after_destroy on the initial object.
      # Clear the destroy pool.
      @destroy_pool = []
      @initial_destroy = nil
      raise SecurityError.new(message)
    end

    # Checks if a user is permitted to do some action on an object.
    # In the case where no rules are declared for the class, this will check
    # if the object being created/deleted is a pure join table, in which case
    # it will then check for add/remove association rules on the models that
    # it belongs to. If the user has one authorization to add/remove such
    # a resource, then the action is permitted.
    #
    # Args:
    # - user: a User object that responds to roles
    # - object: an object (of class subclass of ActiveRecord)
    # - action - one of :create, :update, :delete, :add, :remove
    # - attributes - the attributes or resource being changed (Array of strings
    #   or symbols) Thus a call to update the array with an empty array is true.
    #
    # Returns:
    # - true or false
    #
    # Raises:
    # - ActionNotSupportedError if action is not supported
    # TODO(bdon): pass in Object instead of its class
    # TODO(bdon): refactor flow of method
    def permit?(user, object, action, attributes = [])

      return true if @disabled

      resource = object.class.to_s.tableize.to_sym

      unless @rules[resource]
        return rule_missing(user, object, action, attributes)
      end

      # Choose a collection of permitted roles based on the action.
      # For Updates, this is the union of the universal updaters
      # (who can modify all columns that inherit from ActiveRecord) and the
      # updaters list.
      case action
      when :create
        collection = @rules[resource].creators.merge(@universal_creators)
      when :update
        # TODO(bdon): overwrites? check the logic on this vs just doing
        # OR on check permissions with both collections
        collection = @rules[resource].updaters.merge(@universal_updaters)
      when :delete
        # Add the object to the destroy pool
        # If initial flag is true (first object being destroyed)
        # Mark it as initial
        @destroy_pool << object
        @initial_destroy = object unless @initial_destroy
        return true if destroy_is_dependent?(resource, object)
        collection = @rules[resource].deleters.merge(@universal_deleters)
      when :add
        collection = @rules[resource].resource_adders
      when :remove
        collection = @rules[resource].resource_removers
      else
        raise ActionNotSupportedError, 'action not supported'
      end

      collection = filter_exclusives(collection, resource, object)

      # Finally, check if the user is in the permitted collection
      # for the action on the object.
      return check_permissions(user, collection, object, attributes)
    end

    private

    # Case where there are no rules declared. A few things may happen:
    # - Trying to update columns that are universally updatable.
    # In this case, check against universal_updaters.
    #
    # - Trying to create or delete a join model, in which case the action
    # is rewritten to add/remove and permit is called again for
    # models that it belongs_to.
    #
    # - Otherwise, fail immediately.
    def rule_missing(user, object, action, attributes)

      unless object.class.ancestors.include? ActiveRecord::Base
        raise ActionNotSupportedError, "can't secure non-ActiveRecord class"
      else
        case action
        when :update
          if check_permissions(user, @universal_updaters, object, attributes)
            return true
          end
        when :create
          if check_permissions(user, @universal_creators, object, attributes)
            return true
          end
          action = :add
        when :delete
          if check_permissions(user, @universal_deleters, object, attributes)
            return true
          end
          action = :remove
        else
          return false
        end

        owners = object.class.reflect_on_all_associations(:belongs_to)
        owners.each do |from|
          owners.each do |to|
            # TODO(bdon): put in case where we can call Permit on a class
            # this makes more sense for CREATE operations,
            # since there should never be any instance ACLs returned
            next if from.options[:polymorphic]
            if permit?(user, from.klass.new, action, [to.name])
              return true
            end
          end
        end
        return false
      end
      raise ActionNotSupportedError, 'action not supported'
    end

    # Check the list of dependencies if any are declared in auth rules.
    # Check if the dependency is in the global destroy pool.
    #
    # Args:
    # - resource: name of the current resource (symbol)
    # - object - the object being destroyed
    #
    # returns:
    # - false if there are no dependencies
    # - true if any named dependency is in the destroy pool
    # - false otherwise
    def destroy_is_dependent?(resource, object)
      return false if @rules[resource].dependencies.empty?
      return  @rules[resource].dependencies.inject(false) do |result, dep|
        result || @destroy_pool.include?(unwrap(object,dep))
      end
    end

    # Filter the role lists if there is an exclusive role.
    # The steps are:
    # If there is an exclusive role declared
    #   For each exclusive role declared, check if there exists such a role
    #   on the object instance in the database
    #     If there does not exist any applicable roles
    #       Continue with the collection unchanged
    #     If there is at least one applicable exclusive role
    #       Filter the collection to only include exclusive roles
    def filter_exclusives(collection, resource, object)
      unless @rules[resource].exclusive_roles.empty?
        exclusions = @rules[resource].exclusive_roles.select do |role_name|
          AuthorizationRole.applicable_to(object).find_by_name(
             role_name.to_s)
        end
        unless exclusions.empty?
          collection = collection.reject do |key,value|
            !exclusions.include?(key)
          end
        end
      end
      return collection
    end

    # TODO(bdon): these kinds of functions (finding all roles permitted
    # to do an action) will need to be generalized, to support cdb acl query
    # system (see nickesk's ACL ideas design doc)
    # Possibly refactor check_permission methods to use these instead,
    # since functions are unnecessarily duplicated
    def roles_permitted_to(action, rule, object, attributes)
      return [] if rule.nil?
      case action
      when 'create'
        permissions = rule.creators
      when 'update'
        permissions = rule.updaters.merge(@universal_updaters)
      when 'delete'
        permissions = rule.deleters
      end

      permissions.select do |role, opt|
        permissions[role].inject(false) do |result, role_options|
          result || attributes_in_only_list(attributes, role_options)
        end
      end
    end

    def check_permissions(user, permissions, object, attributes)
      permissions.keys.inject(false) do |result, role|
        result || check_permission(permissions[role], role, user,
                                   object, attributes)
      end
    end

    # TODO(bdon): clean up order of parameters
    def check_permission(permission, role, user, object, attributes)
      permission.inject(false) do |result, role_options|

        # Rewrite the target if a delegate object is given.
        if role_options[:of_associated]
          target = delegate_to(role_options[:of_associated], object)
        elsif role_options[:of_class]
          target = delegate_to(role_options[:of_class], object)
          #now target is a class name
          target = target.constantize.new
        else
          target = object
        end
        return false if target.nil?

        result || (user_has_role_on?(target, user, role) &&
                   attributes_in_only_list(attributes, role_options)) &&
                   user_is_in?(object,
                   role_options[:if_user_in_associated], user) &&
                   attribute_nil?(object, role_options[:if_no])
      end
    end

    def delegate_to(associated, object)
      target = unwrap(object, associated)
    end

    # TODO(bdon): make this role implementation agnostic, and faster
    # Determine if user has been granted an AuthorizationRole named
    # role_name that is scoped on object.
    #
    # Args:
    #  - object - a Securable ActiveRecord
    #  - user - A Grantee
    #  - role_name - a symbol defined in configuration
    #
    # Returns:
    #  - true if the user has a role named role_name
    def user_has_role_on?(object, user, name)
      return false if !user
      return true if :all == name
      AuthorizationRole.held_by(user).applicable_to(object).named(name).size > 0
    end

    # Checks if an associated is nil.
    # args:
    #  - object - the object being queried.
    #  - associated: a nested hash of symbols that is sent to the object.
    # returns:
    #  - false if the object evaluates to a non nil. true if nil.
    # raises:
    #  - NoMethodError on nonexistent association.
    #
    def attribute_nil?(object, associated)
      return true unless associated
      unwrap(object,associated) ? false : true
    end

    def attributes_in_only_list(attributes, options)
      if options[:only]
        (attributes.symbolize! - options[:only]).empty?
      else
        true
      end
    end

    # Check if the current user is in some Collection.
    # the collection specified must respond to includes?
    # If at any point in the chain there is a NoMethodError,
    # the error propagates.
    # Arguments:
    # - object: object being accessed
    # - associated: value of options hash (if nil, no rule declared: true)
    # - user: the current user
    #
    # Return:
    # - true if no option declared
    # - true if option declared and returns true on includes? user
    # - false otherwise
    def user_is_in?(object, associated, user)
      return true unless associated
      target = unwrap(object, associated)
      return target.include?(user)
    end

    # Unwrap hash onto object
    # raises NoMethodError
    def unwrap(object, hshsym)
      while hshsym.is_a? Hash
        object = object.send(hshsym.keys.first)
        hshsym = hshsym.values.first
      end
      object = object.send(hshsym)
    end

  end

  # The ResourceRule class holds authorization rules for one class.
  class ResourceRule

    attr_accessor :creators, :deleters, :updaters, :resource_adders,
                  :resource_removers, :exclusive_roles, :dependencies

    def initialize
      # Role names that have access to create/delete objects of a class.
      @creators = {}
      @deleters = {}
      # Role names that have access to update all columns,
      # or update specific columns (using the :only => option)
      @updaters = {}
      # Role names that have access to add/remove associated resources,
      # resource specified by the :only => option.
      @resource_adders = {}
      @resource_removers = {}
      # Roles names that are exclusive on a class.
      @exclusive_roles = []
      # Dependencies that are declared in auth file
      @dependencies = []
    end

  end

end
