# frozen_string_literal: true

require "set"

module ::AccountSecurity
  module AccountCorrelationService
    module_function

    MAX_NETWORK_GROUP_USERS = 20
    MAX_CANDIDATES_PER_OBSERVATION = 50
    MAX_SHARED_NETWORKS_IN_PAYLOAD = 8
    MAX_SHARED_IPS_IN_PAYLOAD = CoreIpEvidence::MAX_STORED_SHARED_IPS

    def observe!(user:, ip:, trigger:, network: nil, session_signature: nil)
      return [] unless enabled?
      return [] if user.blank? || !user.human? || user.staged? || user.id.to_i <= 0

      normalized_ip = IpNormalizer.normalize(ip)
      return [] if normalized_ip.blank?
      public_ip = IpNormalizer.normalize_public(normalized_ip)
      network ||= IpNormalizer.familiarity_network(public_ip) if public_ip.present?

      candidate_ids = Set.new
      CoreIpEvidence.candidate_user_ids_for_ip(
        normalized_ip,
        current_user_id: user.id,
        max_group_users: MAX_NETWORK_GROUP_USERS,
      ).each { |id| candidate_ids << id }

      if network.present?
        add_small_group_ids!(candidate_ids, UserNetwork.where(network_key: network), user.id)
      end

      if session_signature
        add_small_group_ids!(
          candidate_ids,
          SessionSignature.where(
            network_key: session_signature.network_key,
            signature_hash: session_signature.signature_hash,
          ),
          user.id,
        )
      end

      existing_other_user_ids(user.id).each { |id| candidate_ids << id }

      candidate_ids.delete(user.id)
      candidate_ids.to_a.first(MAX_CANDIDATES_PER_OBSERVATION).filter_map do |other_id|
        recalculate_pair!(user.id, other_id, observed_at: Time.zone.now, source: trigger.to_s)
      end
    rescue StandardError => e
      Rails.logger.warn("[account_security] account correlation observation failed class=#{e.class}")
      []
    end

    def recalculate_pair!(first_user_id, second_user_id, observed_at: nil, source: nil, precomputed_ip_details: nil, precomputed_supplemental: nil)
      return nil unless enabled?

      user_a_id, user_b_id = [first_user_id.to_i, second_user_id.to_i].sort
      return nil if user_a_id <= 0 || user_a_id == user_b_id

      users = User.human_users.where(id: [user_a_id, user_b_id], staged: false).index_by(&:id)
      user_a = users[user_a_id]
      user_b = users[user_b_id]
      return nil if user_a.blank? || user_b.blank?

      evidence = build_evidence(
        user_a,
        user_b,
        precomputed_ip_details: precomputed_ip_details,
        precomputed_supplemental: precomputed_supplemental,
      )
      result = AccountCorrelationPolicy.score_with_breakdown(evidence)
      score = result[:score]
      evidence["score_breakdown"] = result[:breakdown]
      confidence = AccountCorrelationPolicy.confidence(score)
      existing = AccountCorrelation.find_by(user_a_id: user_a_id, user_b_id: user_b_id)
      return nil if existing.blank? && !AccountCorrelationPolicy.store_candidate?(score, evidence)

      now = observed_at || Time.zone.now
      correlation = existing || AccountCorrelation.new(
        user_a_id: user_a_id,
        user_b_id: user_b_id,
        first_seen_at: now,
        status: "open",
      )
      correlation.assign_attributes(
        score: score,
        confidence: confidence,
        evidence: evidence.merge("last_source" => safe_source(source)),
        last_seen_at: [correlation.last_seen_at, now].compact.max,
      )
      created = correlation.new_record?
      correlation.save!
      Statistics.increment!(correlation_candidates: 1) if created
      correlation
    rescue ActiveRecord::RecordNotUnique
      recalculate_pair!(
        user_a_id,
        user_b_id,
        observed_at: observed_at,
        source: source,
        precomputed_ip_details: precomputed_ip_details,
        precomputed_supplemental: precomputed_supplemental,
      )
    rescue StandardError => e
      Rails.logger.warn("[account_security] account correlation recalculation failed class=#{e.class}")
      nil
    end

    def build_evidence(user_a, user_b, precomputed_ip_details: nil, precomputed_supplemental: nil)
      exact_details =
        if precomputed_ip_details.nil?
          CoreIpEvidence.shared_details_for_pair(user_a.id, user_b.id)
        else
          Array(precomputed_ip_details)
        end

      if precomputed_supplemental.is_a?(Hash)
        shared_networks = Array(precomputed_supplemental["shared_networks"]).map(&:to_s).uniq
        shared_signature_count = precomputed_supplemental["shared_session_signature_count"].to_i
        browser = {
          count: precomputed_supplemental["browser_continuity_count"].to_i,
          max_users: precomputed_supplemental["max_browser_continuity_users"].to_i,
        }
        max_network_users = precomputed_supplemental["max_shared_network_users"].to_i
      else
        shared_networks = shared_network_keys(user_a.id, user_b.id).reject { |network| trusted_network?(network) }
        shared_signature_count = shared_session_signatures(user_a.id, user_b.id, shared_networks).length
        browser = BrowserContinuityRecorder.shared_summary(user_a.id, user_b.id)
        max_network_users = shared_networks.map { |network| distinct_users_on_network(network) }.max.to_i
      end

      registration_details = exact_details.select { |detail| both_source?(detail, "registration") }
      current_details = exact_details.select { |detail| both_source?(detail, "current") }
      history_details = exact_details.select { |detail| historical_source?(detail) }
      public_details = exact_details.select { |detail| detail["public"] == true }
      untrusted_public_details = public_details.reject { |detail| detail["trusted"] == true }
      nonpublic_details = exact_details.reject { |detail| detail["public"] == true }
      trusted_details = exact_details.select { |detail| detail["trusted"] == true }

      exact_counts = exact_details.map { |detail| detail["user_count"].to_i }
      registration_delta = ((user_a.created_at - user_b.created_at).abs / 60).round

      {
        "shared_registration_ip" => registration_details.any?,
        "shared_registration_ip_public" => registration_details.any? { |detail| detail["public"] == true && detail["trusted"] != true },
        "shared_registration_ip_nonpublic" => registration_details.any? { |detail| detail["public"] != true },
        "same_current_ip" => current_details.any?,
        "same_current_ip_public" => current_details.any? { |detail| detail["public"] == true && detail["trusted"] != true },
        "shared_exact_ip_count" => exact_details.length,
        "shared_public_ip_count" => public_details.length,
        "untrusted_public_ip_count" => untrusted_public_details.length,
        "shared_nonpublic_ip_count" => nonpublic_details.length,
        "shared_history_ip_count" => history_details.length,
        "shared_auth_ip_count" => exact_details.count { |detail| auth_source?(detail) },
        "trusted_shared_ip_count" => trusted_details.length,
        "tor_shared_ip_count" => exact_details.count { |detail| detail["tor"] == true },
        "hosting_shared_ip_count" => exact_details.count { |detail| detail["hosting"] == true },
        "mobile_shared_ip_count" => exact_details.count { |detail| detail["mobile"] == true },
        "local_blacklist_shared_ip_count" => exact_details.count { |detail| detail["local_blacklist"] == true },
        "shared_ip_details" => exact_details.first(MAX_SHARED_IPS_IN_PAYLOAD),
        "shared_network_count" => shared_networks.length,
        "shared_networks" => shared_networks.first(MAX_SHARED_NETWORKS_IN_PAYLOAD),
        "shared_session_signature_count" => shared_signature_count,
        "browser_continuity_count" => browser[:count].to_i,
        "max_browser_continuity_users" => browser[:max_users].to_i,
        "browser_continuity_positive_only" => true,
        "registration_delta_minutes" => registration_delta,
        "max_shared_network_users" => [max_network_users, exact_counts.max.to_i].max,
        "max_shared_exact_ip_users" => exact_counts.max.to_i,
        "large_shared_network" => [max_network_users, exact_counts.max.to_i].max >= 10,
        "raw_user_agent_stored" => false,
      }
    end

    def shared_network_keys(user_a_id, user_b_id)
      cutoff = SessionSignatureRecorder.retention_cutoff
      a = Set.new(UserNetwork.where(user_id: user_a_id).where("last_seen_at >= ?", cutoff).pluck(:network_key).map(&:to_s))
      b = Set.new(UserNetwork.where(user_id: user_b_id).where("last_seen_at >= ?", cutoff).pluck(:network_key).map(&:to_s))
      a.merge(SessionSignature.where(user_id: user_a_id).where("last_seen_at >= ?", cutoff).pluck(:network_key).map(&:to_s))
      b.merge(SessionSignature.where(user_id: user_b_id).where("last_seen_at >= ?", cutoff).pluck(:network_key).map(&:to_s))
      (a & b).to_a.sort
    end

    def shared_session_signatures(user_a_id, user_b_id, allowed_networks)
      return [] if allowed_networks.blank?
      cutoff = SessionSignatureRecorder.retention_cutoff
      a = SessionSignature.where(user_id: user_a_id, network_key: allowed_networks).where("last_seen_at >= ?", cutoff).pluck(:network_key, :signature_hash).map { |network, signature| [network.to_s, signature] }.to_set
      b = SessionSignature.where(user_id: user_b_id, network_key: allowed_networks).where("last_seen_at >= ?", cutoff).pluck(:network_key, :signature_hash).map { |network, signature| [network.to_s, signature] }.to_set
      (a & b).to_a
    end

    def distinct_users_on_network(network)
      ids = UserNetwork.where(network_key: network).distinct.pluck(:user_id)
      ids |= SessionSignature.where(network_key: network).distinct.pluck(:user_id)
      ids.length
    end

    def add_small_group_ids!(target, scope, current_user_id)
      ids = scope.distinct.limit(MAX_NETWORK_GROUP_USERS + 1).pluck(:user_id).uniq
      return if ids.length > MAX_NETWORK_GROUP_USERS
      ids.each { |id| target << id if id.to_i > 0 && id != current_user_id }
    end

    def existing_other_user_ids(user_id)
      first = AccountCorrelation.where(user_a_id: user_id).limit(MAX_CANDIDATES_PER_OBSERVATION).pluck(:user_b_id)
      second = AccountCorrelation.where(user_b_id: user_id).limit(MAX_CANDIDATES_PER_OBSERVATION).pluck(:user_a_id)
      (first + second).uniq.first(MAX_CANDIDATES_PER_OBSERVATION)
    end

    def both_source?(detail, source)
      Array(detail["sources_a"]).include?(source) && Array(detail["sources_b"]).include?(source)
    end

    def historical_source?(detail)
      sources = Array(detail["sources_a"]) | Array(detail["sources_b"])
      (sources & %w[history auth_session active_session]).any?
    end

    def auth_source?(detail)
      sources = Array(detail["sources_a"]) | Array(detail["sources_b"])
      (sources & %w[auth_session active_session]).any?
    end

    def trusted_network?(network)
      TrustedNetwork.active.where("?::inet <<= network", network.to_s).exists?
    rescue ActiveRecord::StatementInvalid
      false
    end

    def safe_source(value)
      token = value.to_s
      token.match?(/\A[a-z0-9_:-]{1,40}\z/i) ? token : nil
    end

    def enabled?
      SiteSetting.account_security_enabled && SiteSetting.account_security_account_correlation_enabled
    end
  end
end
