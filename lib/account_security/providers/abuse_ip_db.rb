# frozen_string_literal: true
require "json"
require "net/http"
require "openssl"
require "uri"

module ::AccountSecurity
  module Providers
    class AbuseIpDb
      class ResponseTooLarge < StandardError; end
      class InvalidCredential < StandardError; end

      Result = Struct.new(:success, :status, :data, :error_code, :latency_ms, :headers, keyword_init: true)

      CHECK_URI = URI("https://api.abuseipdb.com/api/v2/check")
      BLACKLIST_URI = URI("https://api.abuseipdb.com/api/v2/blacklist")
      REPORT_URI = URI("https://api.abuseipdb.com/api/v2/report")
      MAX_CHECK_BYTES = 256 * 1024
      MAX_BLACKLIST_BYTES = 5 * 1024 * 1024
      MAX_RETRY_AFTER_SECONDS = 24.hours.to_i
      MAX_RATE_RESET_FUTURE_SECONDS = 48.hours.to_i
      USER_AGENT = "Discourse-Account-Security/#{::AccountSecurity::PLUGIN_VERSION}"

      def check(ip)
        expected_ip = IpNormalizer.normalize_public(ip)
        return invalid_ip_result if expected_ip.blank?

        uri = CHECK_URI.dup
        uri.query = URI.encode_www_form(
          ipAddress: expected_ip,
          maxAgeInDays: SiteSetting.account_security_abuseipdb_max_age_days.to_i.clamp(1, 365),
        )
        request = Net::HTTP::Get.new(uri.request_uri)
        perform(uri, request, endpoint: "check", max_bytes: MAX_CHECK_BYTES) do |parsed|
          normalize_check(parsed, expected_ip: expected_ip)
        end
      end

      def blacklist
        uri = BLACKLIST_URI.dup
        request = Net::HTTP::Get.new(uri.request_uri)
        perform(uri, request, endpoint: "blacklist", max_bytes: MAX_BLACKLIST_BYTES) do |parsed|
          normalize_blacklist(parsed)
        end
      end

      def report_bruteforce(ip, observed_at: nil)
        expected_ip = IpNormalizer.normalize_public(ip)
        return invalid_ip_result if expected_ip.blank?

        uri = REPORT_URI.dup
        request = Net::HTTP::Post.new(uri.request_uri)
        request["Content-Type"] = "application/x-www-form-urlencoded"
        request.set_form_data(
          "ip" => expected_ip,
          "categories" => "18",
          "comment" => "Repeated authentication attempts objectively observed by the local Discourse security controls.",
          "timestamp" => (observed_at || Time.zone.now).iso8601,
        )
        perform(uri, request, endpoint: "report", max_bytes: MAX_CHECK_BYTES) do |parsed|
          normalize_report(parsed, expected_ip: expected_ip)
        end
      end

      private

      def perform(uri, request, endpoint:, max_bytes:)
        started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        apply_headers!(request)
        response = nil
        body = nil
        http = http_for(uri)
        Statistics.increment!(provider_calls: 1) if endpoint == "check"
        http.request(request) do |http_response|
          response = http_response
          status = http_response.code.to_i
          # Error and redirect payloads are not used by Account Security. Do
          # not spend memory parsing an untrusted third-party error body; the
          # status and bounded response headers are sufficient for fail-open
          # handling and quota/circuit state.
          body = status.between?(200, 299) ? read_bounded_body(http_response, max_bytes) : ""
        end
        latency = elapsed_ms(started)
        status = response.code.to_i
        headers = normalized_headers(response)
        QuotaManager.record_response(endpoint: endpoint, status: status, headers: headers)

        if status.between?(200, 299)
          parsed = body.present? ? JSON.parse(body) : {}
          data = yield(parsed)
          CircuitBreaker.record_success! if endpoint == "check"
          return Result.new(success: true, status: status, data: data, latency_ms: latency, headers: headers)
        end

        Statistics.increment!(provider_errors: 1) if endpoint == "check"
        handle_failure_status(status, headers, endpoint)
        Result.new(success: false, status: status, data: {}, error_code: error_code_for(status), latency_ms: latency, headers: headers)
      rescue Net::OpenTimeout
        request_failure(:connect_timeout, started, endpoint)
      rescue Net::ReadTimeout
        request_failure(:read_timeout, started, endpoint)
      rescue OpenSSL::SSL::SSLError
        request_failure(:tls_error, started, endpoint)
      rescue SocketError, Errno::ECONNREFUSED, Errno::ECONNRESET, Errno::EHOSTUNREACH, Errno::ENETUNREACH
        request_failure(:network_error, started, endpoint)
      rescue ResponseTooLarge
        request_failure(:response_too_large, started, endpoint)
      rescue InvalidCredential
        request_failure(:invalid_key, started, endpoint, circuit_failure: false)
      rescue JSON::ParserError
        request_failure(:parse_error, started, endpoint)
      rescue StandardError => e
        Rails.logger.warn("[account_security] provider request failed endpoint=#{endpoint} class=#{e.class}")
        request_failure(:network_error, started, endpoint)
      end

      def http_for(uri)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        http.verify_hostname = true if http.respond_to?(:verify_hostname=)
        http.min_version = OpenSSL::SSL::TLS1_2_VERSION if http.respond_to?(:min_version=)
        http.open_timeout = SiteSetting.account_security_connect_timeout_ms.to_i.clamp(250, 5000) / 1000.0
        http.read_timeout = SiteSetting.account_security_read_timeout_ms.to_i.clamp(500, 10_000) / 1000.0
        http.write_timeout = http.read_timeout if http.respond_to?(:write_timeout=)
        http.max_retries = 0 if http.respond_to?(:max_retries=)
        http
      end

      def apply_headers!(request)
        key = SiteSetting.account_security_abuseipdb_api_key.to_s.strip
        raise InvalidCredential if key.blank? || key.bytesize > 1024 || key.match?(/[[:cntrl:]]/)
        request["Accept"] = "application/json"
        request["Key"] = key
        request["User-Agent"] = USER_AGENT
      end

      def read_bounded_body(response, max_bytes)
        content_length = Integer(response["Content-Length"], exception: false)
        raise ResponseTooLarge if content_length && content_length > max_bytes
        body = +""
        response.read_body do |chunk|
          raise ResponseTooLarge if body.bytesize + chunk.bytesize > max_bytes
          body << chunk
        end
        body
      end

      def normalize_check(parsed, expected_ip:)
        data = parsed.is_a?(Hash) ? parsed["data"] : nil
        raise JSON::ParserError, "invalid check payload" unless data.is_a?(Hash)
        returned_ip = IpNormalizer.normalize_public(data["ipAddress"])
        raise JSON::ParserError, "mismatched check IP" unless returned_ip == expected_ip

        score = integer_or_nil(data["abuseConfidenceScore"])
        raise JSON::ParserError, "invalid score" unless score&.between?(0, 100)
        {
          "ipAddress" => returned_ip,
          "abuseConfidenceScore" => score,
          "totalReports" => nonnegative_integer(data["totalReports"]),
          "numDistinctUsers" => nonnegative_integer(data["numDistinctUsers"]),
          "lastReportedAt" => safe_time(data["lastReportedAt"]),
          "usageType" => safe_text(data["usageType"], 120),
          "isp" => safe_text(data["isp"], 160),
          "domain" => safe_text(data["domain"], 160),
          "countryCode" => safe_country(data["countryCode"]),
          "isTor" => data["isTor"] == true,
          "isWhitelisted" => data["isWhitelisted"] == true,
        }.compact
      end

      def normalize_report(parsed, expected_ip:)
        data = parsed.is_a?(Hash) ? parsed["data"] : nil
        raise JSON::ParserError, "invalid report payload" unless data.is_a?(Hash)
        returned_ip = IpNormalizer.normalize_public(data["ipAddress"])
        raise JSON::ParserError, "mismatched report IP" unless returned_ip == expected_ip

        {
          "ipAddress" => returned_ip,
          "abuseConfidenceScore" => integer_or_nil(data["abuseConfidenceScore"]),
        }.compact
      end

      def normalize_blacklist(parsed)
        rows = parsed.is_a?(Hash) ? parsed.dig("data") : nil
        rows = rows["results"] if rows.is_a?(Hash)
        raise JSON::ParserError, "invalid blacklist payload" unless rows.is_a?(Array)
        raise ResponseTooLarge if rows.length > 20_000
        rows.filter_map do |row|
          next unless row.is_a?(Hash)
          ip = IpNormalizer.normalize_public(row["ipAddress"])
          score = integer_or_nil(row["abuseConfidenceScore"])
          next if ip.blank? || score.nil? || !score.between?(0, 100)
          { ip: ip, score: score }
        end
      end

      def handle_failure_status(status, headers, endpoint)
        if endpoint == "check" && status == 429
          now = Time.now
          retry_after = nonnegative_integer(headers["retry-after"])
          retry_after = [retry_after, MAX_RETRY_AFTER_SECONDS].min if retry_after
          reset_epoch = bounded_reset_epoch(headers["x-ratelimit-reset"], now: now)
          until_time = [retry_after && now + retry_after, reset_epoch && Time.at(reset_epoch)].compact.max
          CircuitBreaker.open_until!(until_time) if until_time
        elsif endpoint == "check" && status.in?([401, 403])
          # Invalid/mis-scoped credentials should not be retried on every login.
          # A settings change or the guarded Health reset can release the circuit sooner.
          CircuitBreaker.open_until!(15.minutes.from_now)
        elsif endpoint == "check" && status >= 500
          CircuitBreaker.record_failure!
        end
      end

      def request_failure(code, started, endpoint, circuit_failure: true)
        CircuitBreaker.record_failure! if circuit_failure && endpoint == "check"
        Statistics.increment!(provider_errors: 1) if endpoint == "check"
        Result.new(success: false, status: nil, data: {}, error_code: code, latency_ms: elapsed_ms(started), headers: {})
      end

      def error_code_for(status)
        return :invalid_key if status == 401
        return :access_denied if status == 403
        return :plan_capability if status == 402
        return :quota_exceeded if status == 429
        return :server_error if status >= 500
        return :redirect if status.between?(300, 399)
        :http_error
      end

      def normalized_headers(response)
        %w[x-ratelimit-limit x-ratelimit-remaining x-ratelimit-reset retry-after].to_h { |name| [name, response[name]] }.compact
      end

      def safe_text(value, limit)
        return nil unless value.is_a?(String)
        SafeText.plain(value, max_chars: limit)
      end

      def safe_country(value)
        token = value.to_s.upcase
        token.match?(/\A[A-Z]{2}\z/) ? token : nil
      end

      def safe_time(value)
        text = SafeText.plain(value, max_chars: 128)
        return nil if text.blank?

        Time.zone.parse(text)&.iso8601
      rescue ArgumentError, TypeError
        nil
      end

      def bounded_reset_epoch(value, now: Time.now)
        epoch = nonnegative_integer(value)
        return nil unless epoch

        current = now.to_i
        return nil if epoch < current - 5.minutes.to_i
        return nil if epoch > current + MAX_RATE_RESET_FUTURE_SECONDS

        epoch
      end

      def invalid_ip_result
        Result.new(success: false, status: nil, data: {}, error_code: :invalid_ip, latency_ms: 0, headers: {})
      end

      def integer_or_nil(value)
        Integer(value, exception: false)
      end

      def nonnegative_integer(value)
        n = integer_or_nil(value)
        n && n >= 0 ? n : nil
      end

      def elapsed_ms(started)
        ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
      end
    end
  end
end
