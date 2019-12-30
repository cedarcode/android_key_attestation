# frozen_string_literal: true

require_relative "authorization_list"

module AndroidKeyAttestation
  class KeyDescription
    # https://developer.android.com/training/articles/security-key-attestation#certificate_schema
    ATTESTATION_VERSION_INDEX = 0
    ATTESTATION_SECURITY_LEVEL_INDEX = 1
    KEYMASTER_VERSION_INDEX = 2
    KEYMASTER_SECURITY_LEVEL_INDEX = 3
    ATTESTATION_CHALLENGE_INDEX = 4
    UNIQUE_ID_INDEX = 5
    SOFTWARE_ENFORCED_INDEX = 6
    TEE_ENFORCED_INDEX = 7

    SECURITY_LEVEL_ENUM = {
      0 => :software,
      1 => :trusted_environment,
      2 => :strong_box
    }.freeze

    def initialize(sequence)
      @sequence = sequence
    end

    def attestation_version
      Integer(sequence[ATTESTATION_VERSION_INDEX].value)
    end

    def attestation_security_level
      SECURITY_LEVEL_ENUM.fetch(Integer(sequence[ATTESTATION_SECURITY_LEVEL_INDEX].value))
    end

    def keymaster_version
      Integer(sequence[KEYMASTER_VERSION_INDEX].value)
    end

    def keymaster_security_level
      SECURITY_LEVEL_ENUM.fetch(Integer(sequence[KEYMASTER_SECURITY_LEVEL_INDEX].value))
    end

    def attestation_challenge
      sequence[ATTESTATION_CHALLENGE_INDEX].value
    end

    def unique_id
      sequence[UNIQUE_ID_INDEX].value
    end

    def tee_enforced
      @tee_enforced ||= AuthorizationList.new(sequence[TEE_ENFORCED_INDEX].value)
    end

    def software_enforced
      @software_enforced ||= AuthorizationList.new(sequence[SOFTWARE_ENFORCED_INDEX].value)
    end

    private

    attr_reader :sequence
  end
end
