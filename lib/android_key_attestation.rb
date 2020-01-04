# frozen_string_literal: true

module AndroidKeyAttestation
  class Error < StandardError; end
  class ExtensionMissingError < Error; end
  class ChallengeMismatchError < Error; end
  class CertificateVerificationError < Error; end

  GEM_ROOT = File.expand_path(__dir__)
end

require_relative "android_key_attestation/statement"
require_relative "android_key_attestation/version"
