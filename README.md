# AndroidKeyAttestation

A Ruby gem to verify Android Key attestation statements on your server. Key attestation allows you to verify that the
cryptographic keys you use in apps are stored the a hardware keystore of an Android device.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'android_key_attestation'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install android_key_attestation

## Usage

Request an attestation statement as described in the [Android developer documentation](https://developer.android.com/training/articles/security-key-attestation#verifying) and send the certificate chain to your server application.

In your server application code, do the following:

```ruby
require "android_key_attestation"

statement = AndroidKeyAttestation::Statement.new(certificates)

# Verify the attestation certificate was issued for the challenge you generated
begin
  statement.verify(challenge)
rescue AndroidKeyAttestation::ChallengeMismatchError => e
  # abort
end

# Inspect properties of the attestation certificate belonging to the generated key pair, see
# https://developer.android.com/training/articles/security-key-attestation#certificate_schema_keydescription
# for more details. The gem uses snake_case versions of the lowerCamelCase names in the above link. 
statement.attestation_version
# => 3
statement.attestation_security_level
# => :trusted_environment
statement.tee_enforced.purpose
# => [:sign, :verify]
statement.tee_enforced.origin
# => :generated
statement.software_enforced.creation_date
# => 2018-07-29 08:31:54 -0400
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `bin/rspec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/bdewater/android_key_attestation. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

The gem and its authors are unaffiliated with Google.
