ActiveRecord::Schema.define(:version => 1) do

  create_table 'users', :force => true do |t|
    t.string :name
  end

  create_table 'servers', :force => true do |t|
    t.string :name
    t.boolean :locked
  end

  create_table 'ownerships', :force => true do |t|
    t.references :user
    t.references :server
  end

  create_table 'authorization_roles', :force => true do |t|
    t.string :name, :null => false, :default => ''
    t.string :securable_type, :null => false, :default => ''
    t.integer :securable_id, :null => false, :default => 0
  end

  add_index :authorization_roles, [:name, :securable_type, :securable_id],
            :name => 'index_authorization_roles_for_uniqueness',
            :unique => true

  create_table 'authorization_grants', :force => true do |t|
    t.references :authorization_role
    t.string :grantee_type
    t.integer :grantee_id
  end

  add_index :authorization_grants, [:authorization_role_id, :grantee_type,
                                    :grantee_id],
            :name => 'index_authorization_grants_for_uniqueness',
            :unique => true

  create_table 'under_scores', :force => true do |t|
    t.string :name
    t.boolean :locked
  end

  create_table 'server_items', :force => true do |t|
    t.references :server
  end

  create_table 'server_item_items', :force => true do |t|
    t.references :server_item
  end

end