# frozen_string_literal: true

require "set"

module ::AccountSecurity
  module AccountCorrelationService
    module_function

    MAX_NETWORK_GROUP_USERS = 20
    MAX_CANDIDATES_PER_OBSERVATION = 50
    MAX_SHARED_NETWORKS_IN_PAYLOAD = 8

    def observe!(user:, ip:, trigger:, network: nil, session_signature: nil)
      return [] unless enabled?
      return [] if user.blank? || !user.human? || user.staged? || user.id.to_i <= 0

      normalized_ip = IpNormalizer.normalize_public(ip)
      return [] if normalized_ip.blank?
      network ||= IpNormalizer.familiarity_network(normalized_ip)

      candidate_ids = Set.new
      add_small_group_ids!(candidate_ids, UserNetwork.where(network_key: network), user.id) if network.present?
      add_exact_ip_ids!(candidate_ids, :registration_ip_address, user.registration_ip_address, user.id)
      add_exact_ip_ids!(candidate_ids, :ip_address, normalized_ip, user.id)

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

    def recalculate_pair!(first_user_id, second_user_id, observed_at: nil, source: nil)
      return nil unless enabled?

      user_a_id, user_b_id = [first_user_id.to_i, second_user_id.to_i].sort
      return nil if user_a_id <= 0 || user_a_id == user_b_id

      users = User.human_users.where(id: [user_a_id, user_b_id], staged: false).index_by(&:id)
      user_a = users[user_a_id]
      user_b = users[user_b_id]
      return nil if user_a.blank? || user_b.blank?

      evidence = build_evidence(user_a, user_b)
      score = AccountCorrelationPolicy.score(evidence)
      confidence = AccountCorrelationPolicy.confidence(score)
      existing = AccountCorrelation.find_by(user_a_id: user_a_id, user_b_id: user_b_id)
      return nil if existing.blank? && !AccountCorrelationPolicy.candidate?(score)

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
      recalculate_pair!(user_a_id, user_b_id, observed_at: observed_at, source: source)
    rescue StandardError => e
      Rails.logger.warn("[account_security] account correlation recalculation failed class=#{e.class}")
      nil
    end

    def build_evidence(user_a, user_b)
      shared_networks = shared_network_keys(user_a.id, user_b.id).reject { |network| trusted_network?(network) }
      shared_signatures = shared_session_signatures(user_a.id, user_b.id, shared_networks)
      registration_ip = shared_public_ip(user_a.registration_ip_address, user_b.registration_ip_address)
      current_ip = shared_public_ip(user_a.ip_address, user_b.ip_address)
      registration_ip = nil if registration_ip && trusted_ip?(registration_ip)
      current_ip = nil if current_ip && trusted_ip?(current_ip)

      network_counts = shared_networks.map { |network| distinct_users_on_network(network) }
      registration_count = registration_ip ? User.human_users.where(registration_ip_address: registration_ip).count : 0
      current_count = current_ip ? User.human_users.where(ip_address: current_ip).count : 0
      max_shared_users = (network_counts + [registration_count, current_count]).max.to_i
      registration_delta = ((user_a.created_at - user_b.created_at).abs / 60).round

      {
        "shared_registration_ip" => registration_ip.present?,
        "same_current_ip" => current_ip.present?,
        "shared_network_count" => shared_networks.length,
        "shared_networks" => shared_networks.first(MAX_SHARED_NETWORKS_IN_PAYLOAD),
        "shared_session_signature_count" => shared_signatures.length,
        "registration_delta_minutes" => registration_delta,
        "max_shared_network_users" => max_shared_users,
        "large_shared_network" => max_shared_users >= 10,
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

    def add_exact_ip_ids!(target, column, value, current_user_id)
      ip = IpNormalizer.normalize_public(value)
      return if ip.blank? || trusted_ip?(ip)
      ids = User.human_users.where(column => ip, staged: false).where.not(id: current_user_id).limit(MAX_NETWORK_GROUP_USERS + 1).pluck(:id)
      return if ids.length > MAX_NETWORK_GROUP_USERS
      ids.each { |id| target << id }
    end

    def existing_other_user_ids(user_id)
      first = AccountCorrelation.where(user_a_id: user_id).limit(MAX_CANDIDATES_PER_OBSERVATION).pluck(:user_b_id)
      second = AccountCorrelation.where(user_b_id: user_id).limit(MAX_CANDIDATES_PER_OBSERVATION).pluck(:user_a_id)
      (first + second).uniq.first(MAX_CANDIDATES_PER_OBSERVATION)
    end

    def shared_public_ip(first, second)
      a = IpNormalizer.normalize_public(first)
      b = IpNormalizer.normalize_public(second)
      a.present? && a == b ? a : nil
    end

    def trusted_network?(network)
      TrustedNetwork.active.where("?::inet <<= network", network.to_s).exists?
    rescue ActiveRecord::StatementInvalid
      false
    end

    def trusted_ip?(ip)
      TrustedNetwork.active.where("?::inet <<= network", ip.to_s).exists?
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
