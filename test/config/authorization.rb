# Copyright:: Copyright 2010 Google Inc.
# License:: All Rights Reserved.
# Original Author:: Brandon Liu (mailto:bdon@google.com)

authorization do
  secure :servers do
    creatable_by [:managers, :administrators]
    column [:name], :updatable_by => [:managers, :administrators]
  end
end