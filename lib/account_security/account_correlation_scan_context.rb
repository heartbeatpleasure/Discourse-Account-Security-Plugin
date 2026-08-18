# frozen_string_literal: true

require "ipaddr"
require "set"

module ::AccountSecurity
  class AccountCorrelationScanContext
    MAX_BROWSER_SWITCH_ROWS = 100_000

    attr_reader :diagnostics

    def initialize(cutoff: SessionSignatureRecorder.retention_cutoff)
      @cutoff = cutoff
      @networks_by_user = Hash.new { |hash, user_id| hash[user_id] = Set.new }
      @network_users = Hash.new { |hash, network| hash[network] = Set.new }
      @signatures_by_user = Hash.new { |hash, user_id| hash[user_id] = Set.new }
      @signature_users = Hash.new { |hash, key| hash[key] = Set.new }
      @client_signature_users = Hash.new { |hash, signature| hash[signature] = Set.new }
      @signature_meta_by_user = Hash.new { |hash, user_id| hash[user_id] = {} }
      @session_signature_population_complete = true
      @browser_tokens_by_user = Hash.new { |hash, user_id| hash[user_id] = Set.new }
      @browser_token_users = Hash.new { |hash, token| hash[token] = Set.new }
      @browser_meta_by_user = Hash.new { |hash, user_id| hash[user_id] = {} }
      @browser_switch_rows_by_token = Hash.new { |hash, token| hash[token] = [] }
      @browser_switch_history_complete = true
      @trusted_networks = load_trusted_networks
      @diagnostics = {
        supplemental_network_relations: 0,
        supplemental_signature_relations: 0,
        supplemental_browser_relations: 0,
        browser_switch_rows: 0,
        browser_switch_rows_truncated: false,
        browser_switch_history_complete: true,
        network_pairs_added: 0,
        signature_pairs_added: 0,
      }

      load_networks!
      load_signatures!
      if SiteSetting.account_security_browser_continuity_enabled
        load_browser_continuity!
        load_browser_switches!
      end
    end

    def add_candidate_pairs!(pairs, max_group_users:, max_pairs:)
      diagnostics[:network_pairs_added] = add_group_pairs!(
        pairs,
        @network_users,
        max_group_users: max_group_users,
        max_pairs: max_pairs,
      )
      return diagnostics if pairs.length > max_pairs

      diagnostics[:signature_pairs_added] = add_group_pairs!(
        pairs,
        @signature_users,
        max_group_users: max_group_users,
        max_pairs: max_pairs,
      )
      diagnostics
    end

    def evidence_for_pair(user_a_id, user_b_id)
      user_a_id = user_a_id.to_i
      user_b_id = user_b_id.to_i

      shared_networks = (@networks_by_user[user_a_id] & @networks_by_user[user_b_id]).to_a
      shared_networks.reject! { |network| trusted_network?(network) }
      shared_network_set = shared_networks.to_set

      shared_signature_keys = (@signatures_by_user[user_a_id] & @signatures_by_user[user_b_id]).select do |network, _signature|
        shared_network_set.include?(network)
      end
      signature_summary = observation_summary(
        shared_signature_keys,
        @signature_meta_by_user[user_a_id],
        @signature_meta_by_user[user_b_id],
      )
      shared_client_signatures = shared_signature_keys.map { |_network, signature| signature }.uniq
      max_shared_client_signature_users = shared_client_signatures.map do |signature|
        @client_signature_users[signature].length
      end.max.to_i
      repeated_shared_client_signatures = shared_signature_keys.filter_map do |key|
        row_a = @signature_meta_by_user[user_a_id][key] || {}
        row_b = @signature_meta_by_user[user_b_id][key] || {}
        key[1] if row_a[:observation_count].to_i >= 2 && row_b[:observation_count].to_i >= 2
      end.uniq

      shared_browser_tokens = @browser_tokens_by_user[user_a_id] & @browser_tokens_by_user[user_b_id]
      browser_summary = observation_summary(
        shared_browser_tokens,
        @browser_meta_by_user[user_a_id],
        @browser_meta_by_user[user_b_id],
      )
      max_browser_users = shared_browser_tokens.map { |token| @browser_token_users[token].length }.max.to_i
      browser_switch_rows = shared_browser_tokens.flat_map { |token| @browser_switch_rows_by_token[token] }
      browser_switch_summary =
        BrowserContinuityRecorder
          .switch_summary_from_rows(browser_switch_rows, user_a_id, user_b_id)
          .merge(account_switch_history_complete: @browser_switch_history_complete)
      shared_network_user_counts = shared_networks.index_with { |network| @network_users[network].length }
      max_network_users = shared_network_user_counts.values.max.to_i

      {
        "shared_networks" => shared_networks.sort,
        "shared_session_signature_count" => shared_signature_keys.length,
        "shared_session_client_signature_count" => shared_client_signatures.length,
        "repeated_shared_session_signature_count" => signature_summary[:repeated_count],
        "repeated_shared_session_client_signature_count" => repeated_shared_client_signatures.length,
        "max_shared_session_client_signature_users" => max_shared_client_signature_users,
        "session_client_signature_population_complete" => @session_signature_population_complete,
        "shared_session_signature_paired_observations" => signature_summary[:paired_observations],
        "shared_session_signature_span_days" => signature_summary[:max_span_days],
        "browser_continuity_count" => shared_browser_tokens.length,
        "max_browser_continuity_users" => max_browser_users,
        "repeated_browser_continuity_count" => browser_summary[:repeated_count],
        "browser_continuity_paired_observations" => browser_summary[:paired_observations],
        "browser_continuity_span_days" => browser_summary[:max_span_days],
        "browser_account_switch_count" => browser_switch_summary[:account_switch_count].to_i,
        "browser_account_switch_closest_gap_seconds" => browser_switch_summary[:account_switch_closest_gap_seconds],
        "browser_account_switch_within_1h_count" => browser_switch_summary[:account_switch_within_1h_count].to_i,
        "browser_account_switch_within_6h_count" => browser_switch_summary[:account_switch_within_6h_count].to_i,
        "browser_account_switch_within_24h_count" => browser_switch_summary[:account_switch_within_24h_count].to_i,
        "browser_account_switch_within_7d_count" => browser_switch_summary[:account_switch_within_7d_count].to_i,
        "browser_account_switch_history_complete" => browser_switch_summary[:account_switch_history_complete] == true,
        "max_shared_network_users" => max_network_users,
        # Internal scan-only input used by AccountCorrelationService to derive a
        # v3-ready network signal that does not double count exact-IP overlap.
        # This map is intentionally not persisted in correlation evidence.
        "shared_network_user_counts" => shared_network_user_counts,
      }
    end

    private

    def load_networks!
      UserNetwork
        .where(user_id: eligible_user_ids_scope)
        .where("last_seen_at >= ?", @cutoff)
        .pluck(:user_id, :network_key)
        .each do |user_id, network|
        add_network_relation(user_id, network)
      end
    rescue ActiveRecord::StatementInvalid => e
      Rails.logger.warn("[account_security] correlation scan network preload failed class=#{e.class}")
    end

    def load_signatures!
      SessionSignature
        .where(user_id: eligible_user_ids_scope)
        .where("last_seen_at >= ?", @cutoff)
        .pluck(:user_id, :network_key, :signature_hash, :first_seen_at, :last_seen_at, :observation_count)
        .each do |user_id, network, signature, first_seen_at, last_seen_at, observation_count|
          user_id = user_id.to_i
          network = network.to_s
          signature = signature.to_s
          next if user_id <= 0 || network.blank? || signature.blank?

          add_network_relation(user_id, network)
          key = [network, signature].freeze
          before = @signatures_by_user[user_id].length
          @signatures_by_user[user_id] << key
          @signature_users[key] << user_id
          @client_signature_users[signature] << user_id
          @signature_meta_by_user[user_id][key] = {
            first_seen_at: first_seen_at,
            last_seen_at: last_seen_at,
            observation_count: observation_count.to_i,
          }
          diagnostics[:supplemental_signature_relations] += 1 if @signatures_by_user[user_id].length > before
        end
    rescue ActiveRecord::StatementInvalid => e
      @session_signature_population_complete = false
      Rails.logger.warn("[account_security] correlation scan signature preload failed class=#{e.class}")
    end

    def load_browser_continuity!
      BrowserContinuity
        .where(user_id: eligible_user_ids_scope)
        .where("last_seen_at >= ?", BrowserContinuityRecorder.retention_cutoff)
        .pluck(:user_id, :token_hash, :first_seen_at, :last_seen_at, :observation_count)
        .each do |user_id, token_hash, first_seen_at, last_seen_at, observation_count|
          user_id = user_id.to_i
          token_hash = token_hash.to_s
          next if user_id <= 0 || !BrowserContinuityRecorder.valid_hash?(token_hash)

          before = @browser_tokens_by_user[user_id].length
          @browser_tokens_by_user[user_id] << token_hash
          @browser_token_users[token_hash] << user_id
          @browser_meta_by_user[user_id][token_hash] = {
            first_seen_at: first_seen_at,
            last_seen_at: last_seen_at,
            observation_count: observation_count.to_i,
          }
          diagnostics[:supplemental_browser_relations] += 1 if @browser_tokens_by_user[user_id].length > before
        end
    rescue ActiveRecord::StatementInvalid => e
      Rails.logger.warn("[account_security] correlation scan browser-continuity preload failed class=#{e.class}")
    end


    def load_browser_switches!
      return unless defined?(SessionObservation)

      shared_tokens = @browser_token_users.filter_map do |token, users|
        token if users.length.between?(2, BrowserContinuityRecorder::MAX_GROUP_USERS)
      end
      return if shared_tokens.empty?

      rows =
        SessionObservation
          .where(browser_token_hash: shared_tokens)
          .where("observed_at >= ?", BrowserContinuityRecorder.retention_cutoff)
          .order(:browser_token_hash, :observed_at, :id)
          .limit(MAX_BROWSER_SWITCH_ROWS + 1)
          .pluck(:browser_token_hash, :user_id, :observed_at)
      if rows.length > MAX_BROWSER_SWITCH_ROWS
        @browser_switch_history_complete = false
        diagnostics[:browser_switch_rows_truncated] = true
        rows = rows.first(MAX_BROWSER_SWITCH_ROWS)
      end
      rows.each { |row| @browser_switch_rows_by_token[row[0].to_s] << row }
      diagnostics[:browser_switch_rows] = rows.length
      diagnostics[:browser_switch_history_complete] = @browser_switch_history_complete
    rescue ActiveRecord::StatementInvalid => e
      @browser_switch_history_complete = false
      diagnostics[:browser_switch_history_complete] = false
      Rails.logger.warn("[account_security] correlation scan browser-switch preload failed class=#{e.class}")
    end

    def observation_summary(keys, meta_a, meta_b)
      repeated_count = 0
      paired_observations = 0
      max_span_seconds = 0

      Array(keys).each do |key|
        row_a = meta_a[key] || {}
        row_b = meta_b[key] || {}
        observations_a = row_a[:observation_count].to_i
        observations_b = row_b[:observation_count].to_i
        repeated_count += 1 if observations_a >= 2 && observations_b >= 2
        paired_observations += [observations_a, observations_b].min

        starts = [row_a[:first_seen_at], row_b[:first_seen_at]].compact
        finishes = [row_a[:last_seen_at], row_b[:last_seen_at]].compact
        if starts.any? && finishes.any?
          span = (finishes.max - starts.min).to_i
          max_span_seconds = [max_span_seconds, span].max
        end
      end

      {
        repeated_count: repeated_count,
        paired_observations: paired_observations,
        max_span_days: (max_span_seconds.to_f / 1.day.to_i).floor,
      }
    end

    def add_network_relation(user_id, network)
      user_id = user_id.to_i
      network = network.to_s
      return if user_id <= 0 || network.blank?

      before = @networks_by_user[user_id].length
      @networks_by_user[user_id] << network
      @network_users[network] << user_id
      diagnostics[:supplemental_network_relations] += 1 if @networks_by_user[user_id].length > before
    end

    def add_group_pairs!(pairs, groups, max_group_users:, max_pairs:)
      added = 0
      groups.keys.sort_by { |key| Array(key).map(&:to_s).join("\0") }.each do |key|
        ids = groups[key]
        next if ids.length < 2 || ids.length > max_group_users

        ids.to_a.sort.combination(2) do |pair|
          before = pairs.length
          pairs << pair
          added += 1 if pairs.length > before
          return added if pairs.length > max_pairs
        end
      end
      added
    end

    def load_trusted_networks
      TrustedNetwork.active.pluck(:network).filter_map do |value|
        IPAddr.new(value.to_s)
      rescue IPAddr::InvalidAddressError
        nil
      end
    rescue ActiveRecord::StatementInvalid
      []
    end

    def eligible_user_ids_scope
      User.human_users.where(staged: false).where("users.id > 0").select(:id)
    end

    def trusted_network?(network)
      candidate = IPAddr.new(network.to_s)
      @trusted_networks.any? { |trusted| trusted.include?(candidate) }
    rescue IPAddr::InvalidAddressError
      false
    end
  end
end
