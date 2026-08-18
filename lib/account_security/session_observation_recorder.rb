# frozen_string_literal: true

module ::AccountSecurity
  module SessionObservationRecorder
    module_function

    OBSERVATION_INTERVAL = 24.hours
    MAX_RELATED_USERS = 20
    MUTEX_VALIDITY = 15
    MAX_FUTURE_SKEW = 5.minutes

    def enabled?
      SiteSetting.account_security_enabled &&
        SiteSetting.account_security_account_correlation_enabled &&
        SiteSetting.account_security_session_observation_enabled
    end

    def record!(user_id:, ip:, browser_token_hash: nil, client_signature_hash: nil, observed_at: nil)
      return nil unless enabled?

      user = User.human_users.where(staged: false).find_by(id: user_id.to_i)
      return nil if user.blank? || user.id.to_i <= 0

      normalized_ip = IpNormalizer.normalize(ip)
      return nil if normalized_ip.blank?

      browser_hash = normalized_hash(browser_token_hash)
      client_hash = normalized_hash(client_signature_hash)
      now = Time.zone.now
      observed_time = normalize_time(observed_at) || now
      observed_time = now if observed_time > now + MAX_FUTURE_SKEW

      observation = nil
      DistributedMutex.synchronize(
        "account-security-session-observation-user-#{user.id}",
        validity: MUTEX_VALIDITY,
      ) do
        return nil unless observation_due?(
          user_id: user.id,
          browser_token_hash: browser_hash,
          client_signature_hash: client_hash,
          observed_at: observed_time,
        )

        observation = SessionObservation.create!(
          user_id: user.id,
          ip_address: normalized_ip,
          browser_token_hash: browser_hash,
          client_signature_hash: client_hash,
          observed_at: observed_time,
        )
      end
      return nil unless observation

      if browser_hash.present? && SiteSetting.account_security_browser_continuity_enabled
        BrowserContinuityRecorder.record!(
          user_id: user.id,
          token_hash: browser_hash,
          observed_at: observed_time,
          recalculate: false,
        )
      end

      record_session_signature!(
        user: user,
        ip: normalized_ip,
        client_signature_hash: client_hash,
        observed_at: observed_time,
      )

      recalculate_related_pairs!(
        user_id: user.id,
        ip: normalized_ip,
        browser_token_hash: browser_hash,
        client_signature_hash: client_hash,
        observed_at: observed_time,
      )

      observation
    rescue ActiveRecord::RecordInvalid, ActiveRecord::StatementInvalid => e
      Rails.logger.warn("[account_security] session observation record failed class=#{e.class}")
      nil
    rescue StandardError => e
      Rails.logger.warn("[account_security] session observation processing failed class=#{e.class}")
      nil
    end

    def retention_cutoff
      SiteSetting.account_security_correlation_retention_days.to_i.clamp(30, 730).days.ago
    end

    def observation_due?(user_id:, browser_token_hash:, client_signature_hash:, observed_at:)
      scope = SessionObservation.where(user_id: user_id.to_i)
      latest =
        if browser_token_hash.present?
          scope.where(browser_token_hash: browser_token_hash).order(observed_at: :desc, id: :desc).first
        elsif client_signature_hash.present?
          scope.where(client_signature_hash: client_signature_hash).order(observed_at: :desc, id: :desc).first
        else
          scope.order(observed_at: :desc, id: :desc).first
        end

      return true if latest.blank?
      return true if observed_at - latest.observed_at >= OBSERVATION_INTERVAL

      # A switch between accounts in the same browser profile is valuable
      # positive evidence. The frontend sends immediately on a user change, and
      # this server-side check allows that observation even inside the normal
      # 24-hour heartbeat interval. A different/missing token never subtracts.
      if browser_token_hash.present?
        latest_for_browser =
          SessionObservation
            .where(browser_token_hash: browser_token_hash)
            .order(observed_at: :desc, id: :desc)
            .first
        return true if latest_for_browser.present? && latest_for_browser.user_id.to_i != user_id.to_i
      end

      false
    rescue ActiveRecord::StatementInvalid
      true
    end

    def normalized_hash(value)
      hash = value.to_s
      hash.match?(/\A[0-9a-f]{64}\z/) ? hash : nil
    end

    def normalize_time(value)
      return value.in_time_zone if value.respond_to?(:in_time_zone)
      Time.zone.parse(value.to_s) if value.present?
    rescue ArgumentError, TypeError
      nil
    end

    def record_session_signature!(user:, ip:, client_signature_hash:, observed_at:)
      return if client_signature_hash.blank?

      public_ip = IpNormalizer.normalize_public(ip)
      return if public_ip.blank?
      network = IpNormalizer.familiarity_network(public_ip)
      return if network.blank?

      SessionSignatureRecorder.record_signature!(
        user_id: user.id,
        network: network,
        signature: client_signature_hash,
        observed_at: observed_at,
      )
    end

    def recalculate_related_pairs!(user_id:, ip:, browser_token_hash:, client_signature_hash:, observed_at:)
      candidates = {}

      AccountCorrelationService.existing_other_user_ids(user_id).each do |other_id|
        candidates[other_id.to_i] = 0
      end

      CoreIpEvidence.candidate_user_ids_for_ip(
        ip,
        current_user_id: user_id,
        max_group_users: AccountCorrelationService::MAX_NETWORK_GROUP_USERS,
      ).each do |other_id|
        candidates[other_id.to_i] = [candidates[other_id.to_i] || 99, 1].min
      end

      add_small_group_candidates!(
        candidates,
        SessionObservation.where(browser_token_hash: browser_token_hash).where("observed_at >= ?", retention_cutoff),
        user_id,
        2,
      ) if browser_token_hash.present?

      add_small_group_candidates!(
        candidates,
        SessionObservation.where(client_signature_hash: client_signature_hash).where("observed_at >= ?", retention_cutoff),
        user_id,
        3,
      ) if client_signature_hash.present?

      candidates
        .reject { |id, _priority| id <= 0 || id == user_id.to_i }
        .sort_by { |id, priority| [priority, id] }
        .first(AccountCorrelationService::MAX_CANDIDATES_PER_OBSERVATION)
        .each do |other_id, _priority|
          AccountCorrelationService.recalculate_pair!(
            user_id,
            other_id,
            observed_at: observed_at,
            source: "session_observation",
          )
        end
    end

    def add_small_group_candidates!(target, scope, current_user_id, priority)
      ids =
        scope
          .where.not(user_id: current_user_id.to_i)
          .distinct
          .order(:user_id)
          .limit(MAX_RELATED_USERS + 1)
          .pluck(:user_id)
          .map(&:to_i)
          .uniq
      return if ids.length > MAX_RELATED_USERS

      ids.each do |id|
        next unless id.positive?
        target[id] = [target[id] || 99, priority].min
      end
    rescue ActiveRecord::StatementInvalid
      nil
    end
  end
end
