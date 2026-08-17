# frozen_string_literal: true

require "openssl"

module ::AccountSecurity
  module SessionSignatureRecorder
    module_function

    MAX_USER_AGENT_BYTES = 1024
    CONTEXT = "account_security:session_signature:v1"

    def record_from_token!(user:, token_id:, ip:, seen_at: nil)
      return nil unless SiteSetting.account_security_enabled
      return nil unless SiteSetting.account_security_account_correlation_enabled
      return nil if user.blank? || !user.human? || token_id.blank?

      token = UserAuthToken.find_by(id: token_id, user_id: user.id)
      return nil if token.blank?

      record_token!(user: user, token: token, ip: ip, seen_at: seen_at)
    rescue StandardError => e
      Rails.logger.warn("[account_security] session signature update failed class=#{e.class}")
      nil
    end

    def backfill_active_tokens!
      return 0 unless SiteSetting.account_security_enabled
      return 0 unless SiteSetting.account_security_account_correlation_enabled

      cutoff = retention_cutoff
      count = 0
      UserAuthToken.unexpired.where("rotated_at >= ?", cutoff).find_in_batches(batch_size: 500) do |tokens|
        users = User.human_users.where(id: tokens.map(&:user_id).uniq, staged: false).index_by(&:id)
        tokens.each do |token|
          user = users[token.user_id]
          next if user.blank? || user.id.to_i <= 0
          ip = IpNormalizer.normalize_public(token.client_ip)
          next if ip.blank?

          count += 1 if record_token!(
            user: user,
            token: token,
            ip: ip,
            seen_at: token.rotated_at,
            increment_existing: false,
          )
        end
      end
      count
    rescue StandardError => e
      Rails.logger.warn("[account_security] session signature backfill failed class=#{e.class}")
      0
    end


    def record_token!(user:, token:, ip:, seen_at: nil, increment_existing: true)
      return nil if user.blank? || !user.human? || token.blank? || token.user_id.to_i != user.id.to_i

      normalized_ip = IpNormalizer.normalize_public(ip)
      token_ip = IpNormalizer.normalize_public(token.client_ip)
      return nil if normalized_ip.blank? || token_ip.blank? || normalized_ip != token_ip

      network = IpNormalizer.familiarity_network(normalized_ip)
      signature = signature_for(token.user_agent)
      return nil if network.blank? || signature.blank?

      observed_at = normalize_time(seen_at) || token.rotated_at || token.created_at || Time.zone.now
      record_signature!(
        user_id: user.id,
        network: network,
        signature: signature,
        observed_at: observed_at,
        increment_existing: increment_existing,
      )
    end

    def signature_for(user_agent)
      normalized = normalize_user_agent(user_agent)
      return nil if normalized.blank?

      OpenSSL::HMAC.hexdigest("SHA256", hmac_key, normalized)
    end

    def normalize_user_agent(value)
      value.to_s.gsub(/[[:cntrl:]]+/, " ").squish.byteslice(0, MAX_USER_AGENT_BYTES).presence
    end

    def retention_cutoff
      SiteSetting.account_security_user_network_retention_days.to_i.clamp(30, 365).days.ago
    end

    def record_signature!(user_id:, network:, signature:, observed_at:, increment_existing: true)
      record = SessionSignature.find_or_initialize_by(
        user_id: user_id,
        network_key: network,
        signature_hash: signature,
      )
      if record.new_record?
        record.first_seen_at = observed_at
        record.last_seen_at = observed_at
        record.observation_count = 1
      else
        record.first_seen_at = [record.first_seen_at, observed_at].compact.min
        record.last_seen_at = [record.last_seen_at, observed_at].compact.max
        record.observation_count = record.observation_count.to_i + 1 if increment_existing
      end
      record.save!
      record
    rescue ActiveRecord::RecordNotUnique
      retry_record = SessionSignature.find_by(
        user_id: user_id,
        network_key: network,
        signature_hash: signature,
      )
      retry_record&.update_columns(
        last_seen_at: [retry_record.last_seen_at, observed_at].compact.max,
        observation_count: retry_record.observation_count.to_i + (increment_existing ? 1 : 0),
        updated_at: Time.zone.now,
      )
      retry_record
    end

    def hmac_key
      @hmac_key ||= OpenSSL::HMAC.digest("SHA256", GlobalSetting.safe_secret_key_base, CONTEXT)
    end

    def normalize_time(value)
      return value.in_time_zone if value.respond_to?(:in_time_zone)
      Time.zone.parse(value.to_s) if value.present?
    rescue ArgumentError, TypeError
      nil
    end
  end
end
