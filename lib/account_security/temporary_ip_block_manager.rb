# frozen_string_literal: true

require "digest"
require "ipaddr"

module ::AccountSecurity
  module TemporaryIpBlockManager
    module_function

    class ExistingScreening < StandardError; end
    class NotEligible < StandardError; end

    ALLOWED_DURATIONS = [60, 360, 1_440, 4_320, 10_080].freeze

    def eligible_event?(event)
      event.present? &&
        event.severity.in?(%w[high critical]) &&
        event.evidence_strength.in?(%w[strong corroborated]) &&
        !event.status.in?(%w[benign auto_resolved])
    end

    def create!(event:, actor:, duration_minutes:)
      raise Discourse::InvalidAccess unless actor&.admin?
      raise Discourse::InvalidAccess unless SiteSetting.account_security_temporary_ip_blocks_enabled
      raise NotEligible unless eligible_event?(event)

      duration = Integer(duration_minutes, exception: false)
      raise Discourse::InvalidParameters.new(:duration_minutes) unless ALLOWED_DURATIONS.include?(duration)

      normalized = IpNormalizer.normalize_public(event.ip_address)
      raise Discourse::InvalidParameters.new(:event_id) if normalized.blank?

      mutex_key = "account-security-temp-block-#{Digest::SHA256.hexdigest(normalized)[0, 24]}"
      block = DistributedMutex.synchronize(mutex_key, validity: 15) do
        existing_owned = TemporaryIpBlock.unreleased.where(ip_address: normalized).order(id: :desc).first
        if existing_owned&.expires_at&.future?
          next existing_owned if existing_owned.risk_event_id == event.id
          raise ExistingScreening
        end

        raise ExistingScreening if ScreenedIpAddress.match_for_ip_address(normalized).present?

        screened = nil
        tracked = nil
        TemporaryIpBlock.transaction do
          screened = ScreenedIpAddress.create!(
            ip_address: normalized,
            action_type: ScreenedIpAddress.actions[:block],
          )
          tracked = TemporaryIpBlock.create!(
            risk_event_id: event.id,
            screened_ip_address_id: screened.id,
            ip_address: normalized,
            created_by_id: actor.id,
            expires_at: duration.minutes.from_now,
          )
        end
        tracked
      rescue ActiveRecord::RecordInvalid, ActiveRecord::RecordNotUnique
        raise ExistingScreening
      end

      StaffAudit.log!(
        actor: actor,
        action: "temporary_block_created",
        details: { event_id: event.id, temporary_block_id: block.id, duration_minutes: duration },
      )
      RiskEventAuditTrail.record!(
        event: event,
        action: "temporary_block_created",
        actor: actor,
        details: { temporary_block_id: block.id, duration_minutes: duration },
      )
      block
    end

    def release_for_event!(event:, actor:, reason: "manual")
      raise Discourse::InvalidAccess unless actor&.admin?
      block = TemporaryIpBlock.unreleased.where(risk_event_id: event.id).order(id: :desc).first
      raise Discourse::InvalidParameters.new(:event_id) unless block

      release_record!(block, actor: actor, reason: reason)
    end

    def expire_due!
      TemporaryIpBlock.unreleased.where("expires_at <= ?", Time.zone.now).find_each do |block|
        release_record!(block, actor: nil, reason: "expired")
      end
    end

    def release_record!(block, actor:, reason:)
      normalized = IpNormalizer.normalize_public(block.ip_address)
      mutex_key = "account-security-temp-block-release-#{block.id}"
      released, release_changed = DistributedMutex.synchronize(mutex_key, validity: 15) do
        current = TemporaryIpBlock.find_by(id: block.id)
        next [current, false] if current.blank? || current.released_at.present?

        screened = ScreenedIpAddress.find_by(id: current.screened_ip_address_id)
        release_reason = reason.to_s.first(64)

        TemporaryIpBlock.transaction do
          if screened.blank?
            release_reason = "already_missing"
          elsif !owned_screening?(screened, normalized)
            release_reason = "ownership_mismatch"
          else
            screened.destroy!
          end

          current.update!(released_at: Time.zone.now, release_reason: release_reason)
        end
        [current, true]
      end

      if released && release_changed
        if actor
          StaffAudit.log!(
            actor: actor,
            action: "temporary_block_released",
            details: { event_id: released.risk_event_id, temporary_block_id: released.id, result: released.release_reason },
          )
        end
        event = RiskEvent.find_by(id: released.risk_event_id)
        RiskEventAuditTrail.record!(
          event: event,
          action: "temporary_block_released",
          actor: actor,
          details: { temporary_block_id: released.id, result: released.release_reason },
        ) if event
      end
      released
    rescue StandardError => e
      Rails.logger.warn("[account_security] temporary IP block release failed class=#{e.class}")
      raise if actor
      nil
    end

    def owned_screening?(screened, normalized)
      return false unless screened.action_type == ScreenedIpAddress.actions[:block]
      return false if normalized.blank?

      IPAddr.new(screened.ip_address.to_s).to_s == normalized
    rescue IPAddr::InvalidAddressError, IPAddr::AddressFamilyError
      false
    end
  end
end
