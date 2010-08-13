# Copyright:: Copyright 2010 Google Inc.
# License:: All Rights Reserved.
# Original Author:: Brandon Liu (mailto:bdon@google.com)

require File.join(File.dirname(__FILE__), 'test_helper.rb')

class ReaderTest < ActiveSupport::TestCase

  context 'a basic authorization reader' do
    setup do
      @reader = Authorization::Reader.new
    end

    should 'not have resources for an empty auth file' do
      @reader.parse %{
        authorization do
        end
      }
      assert_equal 0, @reader.resources.size
    end

    should 'secure creating a single resource to one role' do
      @reader.parse %{
        authorization do
          secure :servers do
            creatable_by :manager
            destroyable_by :manager
            updatable_by :manager
          end
        end
      }
      assert_equal 1, @reader.resources.size
      assert @reader.resources[:servers].is_a?(ResourceRule)
      assert_equal 1, @reader.resources[:servers].creators.size
      assert_equal 1, @reader.resources[:servers].deleters.size
      assert_equal 1, @reader.resources[:servers].updaters.size
    end

    should 'secure a single column of one resource' do
      @reader.parse %{
        authorization do
          secure :servers do
            column [:name], :updatable_by => :manager
          end
        end
      }
      assert @reader.resources[:servers].is_a?(ResourceRule)
      assert_equal [:manager], @reader.resources[:servers].updaters.keys
      assert_equal [{:only => [:name]}],
        @reader.resources[:servers].updaters[:manager]
    end

    should 'secure multiple roles with one declaration' do
      @reader.parse %{
        authorization do
          secure :servers do
            creatable_by [:manager, :administrator]
            column [:name], :updatable_by => [:manager, :administrator]
          end
        end
      }
      assert_equal 1, @reader.resources.size, 1
      assert_equal 2, @reader.resources[:servers].creators.size, 2
      assert([:manager, :administrator] -
       @reader.resources[:servers].updaters.keys) == []
      assert_equal [{:only => [:name]}],
        @reader.resources[:servers].updaters[:manager]
      assert_equal [{:only => [:name]}],
        @reader.resources[:servers].updaters[:administrator]
    end

    should 'support manageable as alias for all 3 operations' do
      @reader.parse %{
        authorization do
          secure :servers do
            manageable_by :manager
          end
        end
      }
      assert_equal 1, @reader.resources[:servers].updaters.size
      assert_equal 1, @reader.resources[:servers].creators.size
      assert_equal 1, @reader.resources[:servers].deleters.size
    end

  end

  should 'support declaring rules on associated resources' do
    reader = Authorization::Reader.new
    reader.parse %{
      authorization do
        secure :servers do
          resource [:users], :addable_by => [:manager]
          resource [:users, :devices], :removable_by => [:administrator]
        end
      end
    }
    assert reader.resources[:servers].is_a?(ResourceRule)
    assert_equal([{:only => [:users]}],
                 reader.resources[:servers].resource_adders[:manager])
    removers = reader.resources[:servers].resource_removers[:administrator]
    assert(removers.first[:only] - [:users, :devices] == [])
  end

########### Validations

  context 'erroneous rule configurations' do
    setup do
      @reader = Authorization::Reader.new
    end

    should 'not accept two rule blocks on the same resource' do
      assert_raise(Authorization::DSLError) do
        @reader.parse %{
          authorization do
            secure :servers do
            end
            secure :servers do
            end
          end
        }
      end
    end

    # It seems like a maintainance nightmare to have both singularized
    # and pluralized names. So we'll just reject singulars, and then singularize
    # names of everything
    # also, lowercase/uppercase?
    # since roles will be singular strings in the database, we should
    # enforce that the DSL has plurals, and singularize them
    context 'formatting variations of the ACL config' do
      should 'enforce plural names for HM, HMT, HOT,
              HABTM and singular for HO BT'

      should 'not accept singular resource names' do
        assert_raise Authorization::DSLError do
          @reader.parse %{
            authorization do
              secure :server do
              end
            end
          }
        end
      end

      should 'not accept a non-array for values in :only option hashes' do
        assert_raise(Authorization::DSLError) do
          @reader.parse %{
            authorization do
              secure :servers do
                column :updated_at, :updatable_by => :manager
              end
            end
          }
        end
      end

    end

    should 'raise a DSLError on malformed syntax' do
      assert_raise(Authorization::DSLError) do
        @reader.parse %{
          authorization
          end
        }
      end
      assert_raise(Authorization::DSLError) do
        @reader.parse %{
          authorization do
        }
      end
    end

    should 'parse an actual file' do
      @reader.parse(File.open(File.join(File.dirname(__FILE__),
        'config', 'authorization.rb')))
      assert_equal 1, @reader.resources.size, 1
    end
  end

  context 'dynamic attribute checks' do
    setup do
      @reader = Authorization::Reader.new
    end

  end

  context 'column rules for ActiveRecord base' do

    setup do
      @reader = Authorization::Reader.new
    end

    should 'parse column rules for all classes' do
      assert_nothing_raised do
        @reader.parse %{
          authorization do
            column [:updated_at], :updatable_by => :manager
          end
        }
      end
    end

    should 'apply the global column rule' do
      @reader.parse %{
        authorization do
          column [:updated_at], :updatable_by => :manager
          secure :servers do
          end
        end
      }
      assert_equal [:manager], @reader.universal_updaters.keys
    end

    should 'not allow global rules after a secure block' do
      assert_raise(Authorization::DSLError) do
        @reader.parse %{
          authorization do
            secure :servers do
            end
            column [:updated_at], :updatable_by => :manager
          end
        }
      end
    end

    should 'accept universal create outside of resource blocks' do
      assert_nothing_raised do
        @reader.parse %{
          authorization do
            creatable_by :manager
          end
        }
      end
    end

    should 'accept universal destroy outside of resource blocks' do
      assert_nothing_raised do
        @reader.parse %{
          authorization do
            destroyable_by :manager
          end
        }
      end
    end

    should 'error on column names repeated in both global and class scope'

  end

  context 'exclusive roles' do
    setup do
      @reader = Authorization::Reader.new
    end

    should 'parse exclusive roles correctly' do
      assert_nothing_raised do
        @reader.parse %{
          authorization do
            secure :servers do
              exclusive_role :operator
              updatable_by :operator
            end
          end
        }
      end
      assert_equal [:operator], @reader.resources[:servers].exclusive_roles
    end

  end

  context 'conditions and delegations' do
    setup do
      @reader = Authorization::Reader.new
    end

    should 'parse single delegations correctly' do
      assert_nothing_raised do
        @reader.parse %{
          authorization do
            secure :servers do
              creatable_by :manager, :of_associated => :foo
            end
          end
        }
      end
    end

    should 'parse nested delegations correctly' do
      assert_nothing_raised do
        @reader.parse %{
          authorization do
            secure :servers do
              creatable_by :manager, :of_associated => {:foo => :bar}
            end
          end
        }
      end
    end

    should 'error on bad delegation declared as string' do
      assert_raise DSLError do
        @reader.parse %{
          authorization do
            secure :servers do
              creatable_by :manager, :of_associated => 'Foo'
            end
          end
        }
      end
    end

    should 'error on delegation declared as array' do
      assert_raise DSLError do
        @reader.parse %{
          authorization do
            secure :servers do
              creatable_by :manager, :of_associated => [:foo]
            end
          end
        }
      end
    end

    should 'parse if user in associated correctly' do
      assert_nothing_raised do
        @reader.parse %{
          authorization do
            secure :servers do
              creatable_by :manager, :if_user_in_associated => :root_users
            end
          end
        }
      end
    end

    should 'parse nested if user in associated correctly' do
      assert_nothing_raised do
        @reader.parse %{
          authorization do
            secure :servers do
              creatable_by :manager, :if_user_in_associated =>
                                        {:device => :root_users}
            end
          end
        }
      end
    end

    should 'error on user membership condition declared as string' do
      assert_raise DSLError do
        @reader.parse %{
          authorization do
            secure :servers do
              creatable_by :manager, :if_user_in_associated => 'root_users'
            end
          end
        }
      end
    end

    should 'error on user membership condition declared as array' do
      assert_raise DSLError do
        @reader.parse %{
          authorization do
            secure :servers do
              creatable_by :manager, :if_user_in_associated => [:root_users]
            end
          end
        }
      end
    end

    should 'accept destroyable_if_destroying_associated' do
      assert_nothing_raised do
        @reader.parse %{
          authorization do
            secure :servers do
              destroyable_if_destroying_associated :foo
            end
          end
        }
      end
    end

    should 'accept chained destroyable_if_destroying_associated' do
      assert_nothing_raised do
        @reader.parse %{
          authorization do
            secure :servers do
              destroyable_if_destroying_associated :foo => :bar
            end
          end
        }
      end
    end

  end
end