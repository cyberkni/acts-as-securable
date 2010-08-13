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

module Authorization

  class DSLError < StandardError
  end

  # The DSL parser for ACL configuration.
  # The authorization rules go in a block:
  # authorization do
  # end

  class Reader
    attr_reader :resources, :universal_creators, :universal_updaters,
                :universal_deleters

    def initialize
      # See acts_as_protected.rb:ResourceRule for description
      @universal_updaters = {}
      @universal_creators = {}
      @universal_deleters = {}
      @current_resource_rule = nil
      @current_rule = nil
      @resources = {}
      @current_priv = nil
      @secure_block_entered = false
    end

    def append_resource(resource, rule)
      if @resources[resource]
        raise DSLError, "Can't define authorization rules on a resource twice"
      end
      @resources[resource] = rule
    end

    def authorization(&block)
      self.instance_eval(&block)
    end

    # secure an individual resource.
    #   secure :servers do
    #     creatable_by :managers
    #   end
    def secure(resource)
      # enforce plural
      if resource.to_s.singularize == resource.to_s
        raise DSLError, 'Pluralize resource name'
      end

      # Set a flag that means we've seen a secure block.
      @secure_block_entered = true

      @current_resource_rule = Authorization::ResourceRule.new
      append_resource(resource, @current_resource_rule)
      yield
    ensure
      @current_resource_rule = nil
    end

    def creatable_by(roles, options = {})
      if @current_resource_rule
        add_options @current_resource_rule.creators, roles, options
      else
        universal(@universal_creators, roles, options)
      end
    end

    def destroyable_by(roles, options = {})
      if @current_resource_rule
        add_options @current_resource_rule.deleters, roles, options
      else
        universal(@universal_deleters, roles, options)
      end
    end

    def updatable_by(roles, options = {})
      if @current_resource_rule
        add_options @current_resource_rule.updaters, roles, options
      else
        universal(@universal_updaters, roles, options)
      end
    end

    def universal(collection, roles, options)
      if @secure_block_entered
        raise DSLError, "Can't declare global columns after secure block"
      end
      add_options(collection, roles, options)
    end


    def manageable_by(roles, options = {})
      creatable_by(roles, options)
      destroyable_by(roles, options)
      updatable_by(roles, options)
    end

    def resource(resourcename, hsh)
      if hsh.size != 1 && (hsh.keys.first != :addable_by ||
                           hsh.keys.first != :removable_by)
        raise DSLError, 'invalid resource ACL'
      end

      if hsh.keys.first == :addable_by
        add_options(@current_resource_rule.resource_adders,
          hsh[hsh.keys.first], {:only => resourcename})
      else
        add_options(@current_resource_rule.resource_removers,
          hsh[hsh.keys.first], {:only => resourcename})
      end
    end

    # Declare a role as exclusive for the class; see README
    def exclusive_role(role_name)
      @current_resource_rule.exclusive_roles << role_name
    end


    # Column rules can be declared inside of a secure block (class rule),
    # or before any secure blocks (global rule).
    # A global column rule may not follow any secure blocks.
    #
    # args:
    #  columnnames - the columns to be secured
    #  hsh - :updatable_by => a list of role names
    #
    # raises:
    # - DSLError if the hsh isn't of the form :updatable_by =>
    # - DSLError if a global rule follows a class block

    def column(columnnames, hsh)
      if hsh.size != 1 && (hsh.keys.first != :updatable_by)
        raise DSLError, 'invalid column ACL'
      end


      updatable_by(hsh[:updatable_by], {:only => columnnames})


    end

    def add_options(grantees, role, options)
      if role.is_a?(Array)
        role.each { |r| add_options grantees, r, options }
      else
        check_hash_or_symbol(options[:of_associated])
        check_hash_or_symbol(options[:if_user_in_associated])

        if options[:only]
          raise DSLError, 'need array' unless options[:only].is_a? Array
        end
        grantees[role] ||= []
        grantees[role] << options
      end
    end

    def check_hash_or_symbol(hshsym)
      if hshsym
        unless (hshsym.is_a?(Hash) ||
                hshsym.is_a?(Symbol))
          raise DSLError, 'invalid delegation'
        end
      end
    end

    # Rule to declare that an object is destroyable
    # if it is being destroyed in the context of another object that it
    # belongs to, and on that object dependent => destroy is used.
    def destroyable_if_destroying_associated(dependency)
      if dependency.is_a?(Array)
        dependency.each { |d| destroyable_if_destroying_associated(d) }
      else
        @current_resource_rule.dependencies << dependency
      end
    end

    def parse(input)
      if input.is_a? File
        input = input.read
      end
      self.instance_eval(input)
    rescue SyntaxError, StandardError
      # TODO(bdon): more specific errors
      raise DSLError, 'Illegal DSL syntax'
    end
  end

end
