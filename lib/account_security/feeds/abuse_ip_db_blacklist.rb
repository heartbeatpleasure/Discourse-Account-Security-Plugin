# frozen_string_literal: true

require "digest"

module ::AccountSecurity
  module Feeds
    module AbuseIpDbBlacklist
      module_function

      MUTEX_KEY = "account-security-feed-sync-abuseipdb-blacklist"

      def sync!
        DistributedMutex.synchronize(MUTEX_KEY, validity: 90) { sync_locked! }
      rescue StandardError => e
        mark_failure!(e.class.to_s)
        Rails.logger.warn("[account_security] AbuseIPDB blacklist sync failed class=#{e.class}")
        { success: false, error: "blacklist_sync_failed" }
      end

      def sync_locked!
        return { success: false, skipped: "api_key_missing" } if SiteSetting.account_security_abuseipdb_api_key.blank?

        result = Providers::AbuseIpDb.new.blacklist
        unless result.success
          mark_failure!(result.error_code)
          return { success: false, error: result.error_code.to_s }
        end

        rows = Array(result.data)
        raise "implausible_feed" if rows.empty? || rows.length > 20_000

        replace!(rows)
        { success: true, entry_count: rows.length }
      end

      def replace!(rows)
        generation = SecureRandom.hex(12)
        now = Time.zone.now
        checksum = Digest::SHA256.hexdigest(rows.sort_by { |row| row[:ip] }.map { |row| "#{row[:ip]}:#{row[:score]}" }.join("\n"))
        FeedEntry.transaction do
          values = rows.map do |row|
            {
              source: "abuseipdb_blacklist",
              ip_address: row[:ip],
              score: row[:score],
              generation: generation,
              created_at: now,
              updated_at: now,
            }
          end
          values.each_slice(1000) { |slice| FeedEntry.upsert_all(slice, unique_by: :idx_as_feed_source_ip) }
          FeedEntry.where(source: "abuseipdb_blacklist").where.not(generation: generation).delete_all
          snapshot = FeedSnapshot.find_or_initialize_by(source: "abuseipdb_blacklist")
          snapshot.update!(fetched_at: now, checksum: checksum, entry_count: rows.length, status: "healthy", error_code: nil)
        end
      end

      def mark_failure!(code)
        snapshot = FeedSnapshot.find_or_initialize_by(source: "abuseipdb_blacklist")
        snapshot.update!(status: "error", error_code: code.to_s.first(64))
      rescue StandardError
        nil
      end
    end
  end
end
