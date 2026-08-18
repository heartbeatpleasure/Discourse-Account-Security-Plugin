# frozen_string_literal: true

module ::AccountSecurity
  module SafeText
    module_function

    MARKDOWN_META = /[\\`*_\[\]{}()<>#+.!|~\-]/

    def plain(value, max_chars:)
      max = max_chars.to_i
      return nil if max <= 0 || value.nil?

      text = value.to_s.scrub("�").gsub(/[[:cntrl:]]+/, " ").squish
      return nil if text.blank?

      text.each_char.take(max).join.presence
    rescue EncodingError, ArgumentError
      nil
    end

    def markdown_plain(value, max_chars:)
      text = plain(value, max_chars: max_chars)
      return nil if text.blank?

      # Provider/cache text can eventually be rendered by Discourse Markdown in
      # a staff PM. Escape formatting characters and neutralize @ mentions so
      # external text stays data rather than becoming active message syntax.
      text = text.gsub(MARKDOWN_META) { |char| "\\#{char}" }
      text.gsub("@", "＠")
    end
  end
end
