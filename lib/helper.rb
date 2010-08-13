# Copyright:: Copyright 2010 Google Inc.
# License:: All Rights Reserved.
# Original Author:: Brandon Liu (mailto:bdon@google.com)

class Array
  def symbolize!
    self.map! do |e|
      if e.is_a? String
        e.to_sym
      else
        e
      end
    end
  end
end