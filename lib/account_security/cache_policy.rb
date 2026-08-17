# frozen_string_literal: true
module ::AccountSecurity
  module CachePolicy
    module_function

    def ttl_for(risk_level)
      case risk_level.to_s
      when "elevated" then 12.hours
      when "high" then 6.hours
      when "critical" then 1.hour
      else 24.hours
      end
    end

    def fresh?(record)
      record.present? && record.next_check_after.present? && record.next_check_after > Time.zone.now
    end
  end
end
