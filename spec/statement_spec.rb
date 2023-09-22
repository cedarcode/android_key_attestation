# frozen_string_literal: true

RSpec.describe AndroidKeyAttestation::Statement do
  subject { described_class.new(test_certificate) }

  context "#attestation_certificate" do
    it "returns the first certificate in the chain" do
      expect(subject.attestation_certificate.to_pem).to eq(test_certificate.to_pem)
    end
  end

  context "#verify_challenge" do
    it "returns true if the challenge matches" do
      expect(subject.verify_challenge("abc")).to be true
    end

    it "raises an error if the challenge does not match" do
      expect { subject.verify_challenge("foo") }.to raise_error(AndroidKeyAttestation::ChallengeMismatchError)
    end

    it "raises an error if the challenge is of different length" do
      expect { subject.verify_challenge("foobar") }.to raise_error(AndroidKeyAttestation::ChallengeMismatchError)
    end
  end

  context "#verify_certificate_chain" do
    subject { described_class.new(intermediate_certificate) }

    let(:spec_path) { File.join(AndroidKeyAttestation::GEM_ROOT, "..", "spec") }
    let(:root_certificate) do
      OpenSSL::X509::Certificate.new(File.read(File.join(spec_path, "google_software_attestation_root.pem")))
    end
    let(:intermediate_certificate) do
      OpenSSL::X509::Certificate.new(File.read(File.join(spec_path, "google_software_attestation_intermediate.pem")))
    end
    let(:time) { Time.utc(2019, 12, 31) }

    it "returns true if the chain is valid" do
      expect(subject.verify_certificate_chain(root_certificates: [root_certificate], time: time)).to be true
    end

    it "raises error if the chain is not valid" do
      expect { subject.verify_certificate_chain(time: time) }.to(
        raise_error(AndroidKeyAttestation::CertificateVerificationError)
      )
    end
  end

  context "#key_description" do
    it "raises an error is the extension data is missing" do
      expect { described_class.new(OpenSSL::X509::Certificate.new).key_description }.to(
        raise_error(AndroidKeyAttestation::ExtensionMissingError)
      )
    end
  end

  context "#attestation_version" do
    specify do
      expect(subject.attestation_version).to eq(3)
    end
  end

  context "#attestation_security_level" do
    specify do
      expect(subject.attestation_security_level).to eq(:trusted_environment)
    end
  end

  context "#keymaster_version" do
    specify do
      expect(subject.keymaster_version).to eq(4)
    end
  end

  context "#keymaster_security_level" do
    specify do
      expect(subject.keymaster_security_level).to eq(:trusted_environment)
    end
  end

  context "#unique_id" do
    specify do
      expect(subject.unique_id).to eq("")
    end
  end

  context "#tee_enforced" do
    subject { described_class.new(test_certificate).tee_enforced }

    context "#purpose" do
      specify do
        expect(subject.purpose).to match_array([:sign, :verify])
      end
    end

    context "#origin" do
      specify do
        expect(subject.origin).to eq(:generated)
      end
    end
  end

  context "#software_enforced" do
    subject { described_class.new(test_certificate).software_enforced }

    context "#creation_date" do
      specify do
        expect(subject.creation_date).to eq(Time.utc(2018, 07, 29, 12, 31, 54))
      end
    end

    context "#all_applications" do
      specify do
        expect(subject.all_applications).to be false
      end
    end
  end
end
