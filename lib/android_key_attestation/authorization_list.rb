# frozen_string_literal: true

module AndroidKeyAttestation
  class AuthorizationList
    # https://source.android.com/security/keystore/attestation#attestation-extension
    PURPOSE_TAG = 1
    ALGORITHM_TAG = 2
    KEY_SIZE_TAG = 3
    DIGEST_TAG = 5
    PADDING_TAG = 6
    EC_CURVE_TAG = 10
    RSA_PUBLIC_EXPONENT_TAG = 200
    ROLLBACK_RESISTANCE_TAG = 303
    ACTIVE_DATE_TIME_TAG = 400
    ORIGINATION_EXPIRE_DATE_TIME_TAG = 401
    USAGE_EXPIRE_DATE_TIME_TAG = 402
    NO_AUTH_REQUIRED_TAG = 503
    USER_AUTH_TYPE_TAG = 504
    AUTH_TIMEOUT_TAG = 505
    ALLOW_WHILE_ON_BODY_TAG = 506
    TRUSTED_USER_PRESENCE_REQUIRED_TAG = 507
    TRUSTED_CONFIRMATION_REQUIRED_TAG = 508
    UNLOCK_DEVICE_REQUIRED_TAG = 509
    ALL_APPLICATIONS_TAG = 600
    APPLICATION_ID_TAG = 601
    CREATION_DATE_TIME_TAG = 701
    ORIGIN_TAG = 702
    ROOT_OF_TRUST_TAG = 704
    OS_VERSION_TAG = 705
    OS_PATCH_LEVEL_TAG = 706
    ATTESTATION_APPLICATION_ID_TAG = 709
    ATTESTATION_ID_BRAND_TAG = 710
    ATTESTATION_ID_DEVICE_TAG = 711
    ATTESTATION_ID_PRODUCT_TAG = 712
    ATTESTATION_ID_SERIAL_TAG = 713
    ATTESTATION_ID_IMEI_TAG = 714
    ATTESTATION_ID_MEID_TAG = 715
    ATTESTATION_ID_MANUFACTURER_TAG = 716
    ATTESTATION_ID_MODEL_TAG = 717
    VENDOR_PATCH_LEVEL_TAG = 718
    BOOT_PATCH_LEVEL_TAG = 719

    # https://source.android.com/security/keystore/tags
    PURPOSE_ENUM = {
      0 => :encrypt,
      1 => :decrypt,
      2 => :sign,
      3 => :verify,
      4 => :derive_key,
      5 => :wrap_key,
    }.freeze
    ORIGIN_ENUM = {
      0 => :generated,
      1 => :derived,
      2 => :imported,
      3 => :unknown,
    }.freeze

    def initialize(sequence)
      @sequence = sequence
    end

    def purpose
      integers = find_optional_integer_set(PURPOSE_TAG)
      integers&.map { |i| PURPOSE_ENUM.fetch(i) }
    end

    def all_applications
      find_boolean(ALL_APPLICATIONS_TAG)
    end

    def creation_date
      find_time_milliseconds(CREATION_DATE_TIME_TAG)
    end

    def origin
      integer = find_optional_integer(ORIGIN_TAG)
      ORIGIN_ENUM.fetch(integer) if integer
    end

    def find_by_tag(tag)
      sequence.detect { |data| data.tag == tag }
    end

    private

    attr_reader :sequence

    def find_optional_integer_set(tag)
      value = find_by_tag(tag)&.value&.at(0)&.value
      value&.map { |asn1_int| asn1_int.value.to_i }
    end

    def find_optional_integer(tag)
      find_by_tag(tag)&.value&.at(0)&.value&.to_i
    end

    def find_boolean(tag)
      find_by_tag(tag)&.value || false
    end

    def find_time_milliseconds(tag)
      value = find_by_tag(tag)&.value&.at(0)&.value
      Time.at(value.to_i / 1000) if value
    end
  end
end
