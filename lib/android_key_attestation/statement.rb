# frozen_string_literal: true

require "forwardable"
require "openssl"
require_relative "key_description"
require_relative "fixed_length_secure_compare"

module AndroidKeyAttestation
  class Statement
    EXTENSION_DATA_OID = "1.3.6.1.4.1.11129.2.1.17"
    GOOGLE_ROOT_CERTIFICATES = begin
      file = File.read(File.join(GEM_ROOT, "android_key_attestation", "google_hardware_attestation_root.pem"))
      [OpenSSL::X509::Certificate.new(file)]
    end.freeze

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
      attestation_challenge = key_description.attestation_challenge
      attestation_challenge.bytesize == challenge.bytesize &&
        OpenSSL.fixed_length_secure_compare(attestation_challenge, challenge) ||
        raise(ChallengeMismatchError)
    end

    def verify_certificate_chain(root_certificates: GOOGLE_ROOT_CERTIFICATES, time: Time.now)
      store = OpenSSL::X509::Store.new
      root_certificates.each { |cert| store.add_cert(cert) }
      store.time = time

      store.verify(attestation_certificate, @certificates[1..-1]) ||
        raise(CertificateVerificationError, store.error_string)
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
