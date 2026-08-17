# frozen_string_literal: true
module ::AccountSecurity
  module Statistics
    module_function

    COUNTERS = %i[assessments registrations logins manual_lookups provider_calls cache_hits local_blacklist_hits tor_hits quota_skips provider_errors events_created].freeze

    def increment!(values = {})
      safe = COUNTERS.index_with { |key| [values[key].to_i, 0].max }
      now = Time.zone.now
      params = { stat_date: Date.current, created_at: now, updated_at: now }
      COUNTERS.each { |key| params[key] = safe[key] }
      columns = ["stat_date"] + COUNTERS.map(&:to_s) + %w[created_at updated_at]
      updates = COUNTERS.map { |key| "#{key} = account_security_daily_stats.#{key} + EXCLUDED.#{key}" }
      updates << "updated_at = EXCLUDED.updated_at"
      DB.exec(<<~SQL, params)
        INSERT INTO account_security_daily_stats (#{columns.join(', ')})
        VALUES (#{columns.map { |column| ":#{column}" }.join(', ')})
        ON CONFLICT (stat_date) DO UPDATE SET #{updates.join(', ')}
      SQL
    rescue StandardError => e
      Rails.logger.warn("[account_security] statistics update failed class=#{e.class}")
      nil
    end

    def period_payload(days)
      days = [[days.to_i, 7].max, 365].min
      start_date = Date.current - (days - 1).days
      rows = DailyStat.where(stat_date: start_date..Date.current).order(:stat_date).to_a
      totals = COUNTERS.index_with { 0 }
      rows.each { |row| COUNTERS.each { |key| totals[key] += row.public_send(key).to_i } }
      {
        period_days: days,
        start_date: start_date.iso8601,
        end_date: Date.current.iso8601,
        totals: totals,
        daily: rows.map { |row| row_payload(row) },
      }
    rescue ActiveRecord::StatementInvalid
      { period_days: days, totals: COUNTERS.index_with { 0 }, daily: [] }
    end

    def today_payload
      row_payload(DailyStat.find_by(stat_date: Date.current))
    rescue ActiveRecord::StatementInvalid
      row_payload(nil)
    end

    def row_payload(row)
      COUNTERS.index_with { |key| row&.public_send(key).to_i }.merge(stat_date: (row&.stat_date || Date.current).iso8601)
    end
  end
end
