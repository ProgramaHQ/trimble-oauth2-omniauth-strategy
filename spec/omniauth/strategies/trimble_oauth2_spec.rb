# frozen_string_literal: true

require 'spec_helper'

RSpec.describe OmniAuth::Strategies::TrimbleOauth2 do
  subject { described_class.new({}) }

  let(:access_token) { instance_double('OAuth2::AccessToken') }

  let(:rsa_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:jwk) { JWT::JWK.new(rsa_key, kid: 'test-key-1') }
  let(:jwks_hash) { { 'keys' => [jwk.export] } }

  let(:valid_claims) do
    {
      'sub' => '12345',
      'given_name' => 'John',
      'family_name' => 'Doe',
      'email' => 'john.doe@example.com',
      'iss' => 'https://id.trimble.com',
      'iat' => Time.now.to_i,
      'exp' => Time.now.to_i + 3600
    }
  end

  let(:valid_id_token) do
    JWT.encode(valid_claims, rsa_key, 'RS256', { kid: 'test-key-1' })
  end

  before do
    allow(subject).to receive(:access_token).and_return(access_token)
  end

  def stub_jwks_fetch
    allow(subject).to receive(:fetch_jwks).and_return(jwks_hash)
  end

  describe 'client options' do
    it 'has correct site' do
      expect(subject.options.client_options.site).to eq('https://id.trimble.com')
    end

    it 'has correct authorize url' do
      expect(subject.options.client_options.authorize_url).to eq('/oauth/authorize')
    end

    it 'has correct token url' do
      expect(subject.options.client_options.token_url).to eq('/oauth/token')
    end
  end

  describe 'info' do
    before do
      allow(subject).to receive(:raw_info).and_return(valid_claims)
    end

    it 'returns the correct name' do
      expect(subject.info[:name]).to eq('John Doe')
    end

    it 'returns the correct email' do
      expect(subject.info[:email]).to eq('john.doe@example.com')
    end

    it 'returns the correct first_name' do
      expect(subject.info[:first_name]).to eq('John')
    end

    it 'returns the correct last_name' do
      expect(subject.info[:last_name]).to eq('Doe')
    end
  end

  describe 'extra' do
    let(:raw_info) do
      {
        'sub' => '12345',
        'data_region' => 'us-west',
        'picture' => 'https://example.com/picture.jpg'
      }
    end

    before do
      allow(subject).to receive(:raw_info).and_return(raw_info)
    end

    it 'includes raw_info' do
      expect(subject.extra[:raw_info]).to eq(raw_info)
    end

    it 'includes location' do
      expect(subject.extra[:location]).to eq('us-west')
    end

    it 'includes picture' do
      expect(subject.extra[:picture]).to eq('https://example.com/picture.jpg')
    end
  end

  describe 'uid' do
    before do
      allow(subject).to receive(:raw_info).and_return(valid_claims)
    end

    it 'returns the sub from raw_info' do
      expect(subject.uid).to eq('12345')
    end
  end

  describe '#raw_info' do
    context 'when id_token is present and valid' do
      before do
        stub_jwks_fetch
        allow(access_token).to receive(:[]).with('id_token').and_return(valid_id_token)
      end

      it 'decodes and verifies the JWT token' do
        result = subject.send(:raw_info)
        expect(result['sub']).to eq('12345')
        expect(result['given_name']).to eq('John')
        expect(result['family_name']).to eq('Doe')
        expect(result['email']).to eq('john.doe@example.com')
      end
    end

    context 'when id_token is nil' do
      before do
        allow(access_token).to receive(:[]).with('id_token').and_return(nil)
      end

      it 'returns empty hash' do
        expect(subject.send(:raw_info)).to eq({})
      end
    end

    context 'when id_token has invalid signature' do
      let(:attacker_key) { OpenSSL::PKey::RSA.generate(2048) }
      let(:forged_token) do
        JWT.encode(valid_claims, attacker_key, 'RS256', { kid: 'test-key-1' })
      end

      before do
        stub_jwks_fetch
        allow(access_token).to receive(:[]).with('id_token').and_return(forged_token)
      end

      it 'raises a JWT verification error' do
        expect { subject.send(:raw_info) }.to raise_error(JWT::VerificationError)
      end
    end

    context 'when id_token has wrong issuer' do
      let(:wrong_issuer_token) do
        JWT.encode(valid_claims.merge('iss' => 'https://evil.example.com'), rsa_key, 'RS256', { kid: 'test-key-1' })
      end

      before do
        stub_jwks_fetch
        allow(access_token).to receive(:[]).with('id_token').and_return(wrong_issuer_token)
      end

      it 'raises an invalid issuer error' do
        expect { subject.send(:raw_info) }.to raise_error(JWT::InvalidIssuerError)
      end
    end

    context 'when id_token is expired' do
      let(:expired_token) do
        JWT.encode(valid_claims.merge('exp' => Time.now.to_i - 3600), rsa_key, 'RS256', { kid: 'test-key-1' })
      end

      before do
        stub_jwks_fetch
        allow(access_token).to receive(:[]).with('id_token').and_return(expired_token)
      end

      it 'raises an expired signature error' do
        expect { subject.send(:raw_info) }.to raise_error(JWT::ExpiredSignature)
      end
    end

    context 'when id_token uses HS256 (algorithm substitution attack)' do
      before do
        stub_jwks_fetch
        allow(access_token).to receive(:[]).with('id_token').and_return(
          JWT.encode(valid_claims, 'some_secret', 'HS256')
        )
      end

      it 'rejects the token' do
        expect { subject.send(:raw_info) }.to raise_error(JWT::DecodeError)
      end
    end

    context 'when id_token uses alg:none (unsigned)' do
      before do
        stub_jwks_fetch
        header = Base64.urlsafe_encode64({ typ: 'JWT', alg: 'none' }.to_json, padding: false)
        payload = Base64.urlsafe_encode64(valid_claims.to_json, padding: false)
        allow(access_token).to receive(:[]).with('id_token').and_return("#{header}.#{payload}.")
      end

      it 'rejects the token' do
        expect { subject.send(:raw_info) }.to raise_error(JWT::DecodeError)
      end
    end

    context 'when id_token is missing required claims' do
      let(:missing_sub_token) do
        claims = { 'iss' => 'https://id.trimble.com', 'exp' => Time.now.to_i + 3600, 'iat' => Time.now.to_i }
        JWT.encode(claims, rsa_key, 'RS256', { kid: 'test-key-1' })
      end

      before do
        stub_jwks_fetch
        allow(access_token).to receive(:[]).with('id_token').and_return(missing_sub_token)
      end

      it 'raises a missing required claim error' do
        expect { subject.send(:raw_info) }.to raise_error(JWT::MissingRequiredClaim)
      end
    end
  end

  describe '#id_token' do
    before do
      allow(access_token).to receive(:[]).with('id_token').and_return('sample.jwt.token')
    end

    it 'returns the id_token from access_token' do
      expect(subject.send(:id_token)).to eq('sample.jwt.token')
    end
  end

  describe 'JWKS caching' do
    before do
      stub_jwks_fetch
      allow(access_token).to receive(:[]).with('id_token').and_return(valid_id_token)
    end

    it 'caches JWKS keys after first fetch' do
      subject.send(:raw_info)
      subject.instance_variable_set(:@raw_info, nil)
      subject.send(:raw_info)

      expect(subject).to have_received(:fetch_jwks).once
    end
  end
end
