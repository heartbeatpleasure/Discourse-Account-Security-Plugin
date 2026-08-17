# frozen_string_literal: true
module ::AccountSecurity
  module NetworkFamiliarity
    module_function

    def observe!(user:, ip:, registration: false)
      network = IpNormalizer.familiarity_network(ip)
      family = IpNormalizer.family(ip)
      return { new_network: false, network: nil } if user.blank? || network.blank? || family.blank?

      cutoff = SiteSetting.account_security_user_network_retention_days.to_i.clamp(30, 365).days.ago
      record = UserNetwork.find_by(user_id: user.id, network_key: network)
      familiar = record.present? && record.last_seen_at.present? && record.last_seen_at >= cutoff
      now = Time.zone.now
      record ||= UserNetwork.new(
        user_id: user.id,
        network_key: network,
        address_family: family,
        first_seen_at: now,
        successful_login_count: 0,
      )
      record.last_seen_at = now
      record.registration_origin = true if registration
      record.successful_login_count = record.successful_login_count.to_i + 1 unless registration
      record.save!
      { new_network: !familiar, network: network }
    rescue ActiveRecord::RecordNotUnique
      retry_record = UserNetwork.find_by(user_id: user.id, network_key: network)
      { new_network: retry_record.blank? || retry_record.last_seen_at < cutoff, network: network }
    rescue StandardError => e
      Rails.logger.warn("[account_security] familiarity update failed class=#{e.class}")
      { new_network: true, network: network }
    end
  end
end
