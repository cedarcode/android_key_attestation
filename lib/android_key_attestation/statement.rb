# frozen_string_literal: true

require "forwardable"
require "openssl"
require_relative "key_description"
require_relative "fixed_length_secure_compare"

module AndroidKeyAttestation
  class Statement
    EXTENSION_DATA_OID = "1.3.6.1.4.1.11129.2.1.17"

    extend Forwardable
    def_delegators :key_description, :attestation_version, :attestation_security_level, :keymaster_version,
                   :keymaster_security_level, :unique_id, :tee_enforced, :software_enforced

    using FixedLengthSecureCompare

    def initialize(*certificates)
      @certificates = certificates
    end

    def attestation_certificate
      @certificates.first
    end

    def verify_challenge(challenge)
      OpenSSL.fixed_length_secure_compare(key_description.attestation_challenge, challenge) ||
        raise(ChallengeMismatchError)
    end

    def key_description
      @key_description ||= begin
        extension_data = attestation_certificate.extensions.detect { |ext| ext.oid == EXTENSION_DATA_OID }
        raise AndroidKeyAttestation::ExtensionMissingError unless extension_data

        raw_key_description = OpenSSL::ASN1.decode(extension_data).value.last
        KeyDescription.new(OpenSSL::ASN1.decode(raw_key_description.value).value)
      end
    end
  end
end
