# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::SafeText do
  it "normalizes control characters and truncates by characters without breaking UTF-8" do
    value = "  alpha\n\tbeta 🙂🙂🙂 omega  "

    result = described_class.plain(value, max_chars: 14)

    expect(result).to be_valid_encoding
    expect(result).to eq("alpha beta 🙂🙂🙂")
  end

  it "keeps untrusted provider text inert when inserted into staff Markdown" do
    result = described_class.markdown_plain(
      "[status](https://example.invalid) @admins <script> _test_",
      max_chars: 120,
    )

    expect(result).to include("\\[status\\]\\(https://example\\.invalid\\)")
    expect(result).to include("＠admins")
    expect(result).not_to include("@admins")
    expect(result).to include("\\<script\\>")
    expect(result).to include("\\_test\\_")
  end
end
