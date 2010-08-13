# Copyright:: Copyright 2010 Google Inc.
# License:: All Rights Reserved.
# Original Author:: Brandon Liu (mailto:bdon@google.com)

# This module provides mixins to ActiveRecord that are used for role-based
# authorization.

module Authorization

  class SecurityError < RuntimeError
  end

  module  AuthorizationInModel

    def self.included(base)
      base.extend(ClassMethods)
    end

    module ClassMethods

      # install callbacks
      def acts_as_protected

        unless included_modules.include?(InstanceMethods)
          include InstanceMethods
        end

        before_update :protect_update
        before_create :protect_create
        before_destroy :protect_delete

        after_destroy :clear_dependencies

      end

      def acts_as_grantee
        has_many :authorization_grants, :as => :grantee
        has_many :held_roles, :through => :authorization_grants,
                              :source => :authorization_role,
                              :class_name => 'AuthorizationRole'
      end
    end

  end

  ActiveRecord::Base.send(:include, Authorization::AuthorizationInModel)

  module InstanceMethods

    def protect_update
      return true if ActiveRecord::Base.acl_manager.nil?
      unless ActiveRecord::Base.acl_manager.permit?(User.current, self,
                                                     :update, self.changed)
        ActiveRecord::Base.acl_manager.security_error('update', self)
      end
    end

    def protect_create
      return true if ActiveRecord::Base.acl_manager.nil?
      unless ActiveRecord::Base.acl_manager.permit?(User.current, self,
                                                     :create)
        ActiveRecord::Base.acl_manager.security_error('create', self)
      end
    end

    def protect_delete
      return true if ActiveRecord::Base.acl_manager.nil?
      unless ActiveRecord::Base.acl_manager.permit?(User.current, self,
                                                     :delete)
        ActiveRecord::Base.acl_manager.security_error('delete', self)
      end
    end

    def is_allowed_create?(grantee=User.current)
      return true if ActiveRecord::Base.acl_manager.nil?
      return ActiveRecord::Base.acl_manager.permit?(grantee, self, :create)
    end

    def is_allowed_action?(action, grantee)
      return true if ActiveRecord::Base.acl_manager.nil?
      return ActiveRecord::Base.acl_manager.permit?(grantee, self, action)
    end

    # If there was no security violation, clear the destroy pool.
    # The other point of exit is in the security violation method.
    def clear_dependencies
      if self == ActiveRecord::Base.acl_manager.initial_destroy
        ActiveRecord::Base.acl_manager.destroy_pool = []
        ActiveRecord::Base.acl_manager.initial_destroy = nil
      end
    end

  end
end
