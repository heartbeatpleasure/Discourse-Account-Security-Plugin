# frozen_string_literal: true

require "digest"
require "net/http"
require "openssl"
require "uri"

module ::AccountSecurity
  module Feeds
    module TorExitList
      module_function

      URI_ENDPOINT = URI("https://check.torproject.org/torbulkexitlist")
      MAX_BYTES = 2 * 1024 * 1024
      MAX_LINE_BYTES = 128
      MUTEX_KEY = "account-security-feed-sync-tor"

      def sync!
        DistributedMutex.synchronize(MUTEX_KEY, validity: 30) { sync_locked! }
      rescue StandardError => e
        mark_failure!(e.class.to_s)
        Rails.logger.warn("[account_security] Tor feed sync failed class=#{e.class}")
        { success: false, error: "tor_sync_failed" }
      end

      def sync_locked!
        response, body = fetch
        raise "unexpected_status" unless response.code.to_i == 200

        ips = body.each_line.filter_map do |line|
          next if line.bytesize > MAX_LINE_BYTES

          IpNormalizer.normalize_public(line.strip)
        end.uniq
        raise "implausible_feed" if ips.length < 20 || ips.length > 20_000

        replace!(ips)
        { success: true, entry_count: ips.length }
      end

      def replace!(ips)
        generation = SecureRandom.hex(12)
        now = Time.zone.now
        checksum = Digest::SHA256.hexdigest(ips.sort.join("\n"))
        FeedEntry.transaction do
          rows = ips.map do |ip|
            {
              source: "tor",
              ip_address: ip,
              generation: generation,
              created_at: now,
              updated_at: now,
            }
          end
          rows.each_slice(1000) { |slice| FeedEntry.upsert_all(slice, unique_by: :idx_as_feed_source_ip) }
          FeedEntry.where(source: "tor").where.not(generation: generation).delete_all
          snapshot = FeedSnapshot.find_or_initialize_by(source: "tor")
          snapshot.update!(fetched_at: now, checksum: checksum, entry_count: ips.length, status: "healthy", error_code: nil)
        end
      end

      def fetch
        http = Net::HTTP.new(URI_ENDPOINT.host, URI_ENDPOINT.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        http.verify_hostname = true if http.respond_to?(:verify_hostname=)
        http.min_version = OpenSSL::SSL::TLS1_2_VERSION if http.respond_to?(:min_version=)
        http.open_timeout = 2
        http.read_timeout = 5
        http.write_timeout = 5 if http.respond_to?(:write_timeout=)
        http.max_retries = 0 if http.respond_to?(:max_retries=)
        request = Net::HTTP::Get.new(URI_ENDPOINT.request_uri)
        request["User-Agent"] = "Discourse-Account-Security/#{::AccountSecurity::PLUGIN_VERSION}"
        response = nil
        body = +""
        http.request(request) do |r|
          response = r
          status = r.code.to_i
          raise "redirect_not_allowed" if status.between?(300, 399)
          next unless status == 200

          length = Integer(r["Content-Length"], exception: false)
          raise "response_too_large" if length && length > MAX_BYTES
          r.read_body do |chunk|
            raise "response_too_large" if body.bytesize + chunk.bytesize > MAX_BYTES
            body << chunk
          end
        end
        [response, body]
      end

      def mark_failure!(code)
        snapshot = FeedSnapshot.find_or_initialize_by(source: "tor")
        snapshot.update!(status: "error", error_code: code.to_s.first(64))
      rescue StandardError
        nil
      end
    end
  end
end
