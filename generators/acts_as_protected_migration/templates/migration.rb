# Copyright:: Copyright 2010 Google Inc.
# License:: All Rights Reserved.
# Original Author:: Brandon Liu (mailto:bdon@google.com)
#
class ActsAsProtectedMigration < ActiveRecord::Migration

  def self.up
    create_table :authorization_roles do |t|
      t.string :name, :null => false, :default => ''
      t.string :securable_type, :null => false, :default => ''
      t.integer :securable_id, :null => false, :default => 0
      t.timestamps
    end

    add_index :authorization_roles, [:name, :securable_type, :securable_id],
              :name => 'index_authorization_roles_for_uniqueness',
              :unique => true

    create_table :authorization_grants do |t|
      t.references :authorization_role
      t.string :grantee_type
      t.integer :grantee_id
      t.timestamps
    end

    add_index :authorization_grants, [:authorization_role_id, :grantee_type,
                                      :grantee_id],
              :name => 'index_authorization_grants_for_uniqueness',
              :unique => true

    add_index :authorization_grants, [:grantee_id, :grantee_type]
  end

  def self.down
    drop_table :authorization_roles
    drop_table :authorization_grants
  end

end
