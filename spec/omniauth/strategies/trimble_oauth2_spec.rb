# frozen_string_literal: true

require 'spec_helper'

RSpec.describe OmniAuth::Strategies::TrimbleOauth2 do
  subject { described_class.new({}) }

  let(:access_token) { instance_double('OAuth2::AccessToken') }
  let(:parsed_response) { {} }
  let(:response) { instance_double('OAuth2::Response', parsed: parsed_response) }

  before do
    allow(subject).to receive(:access_token).and_return(access_token)
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
    let(:raw_info) do
      {
        'sub' => '12345',
        'given_name' => 'John',
        'family_name' => 'Doe',
        'email' => 'john.doe@example.com'
      }
    end

    before do
      allow(subject).to receive(:raw_info).and_return(raw_info)
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
    let(:raw_info) { { 'sub' => '12345' } }

    before do
      allow(subject).to receive(:raw_info).and_return(raw_info)
    end

    it 'returns the sub from raw_info' do
      expect(subject.uid).to eq('12345')
    end
  end

  describe '#raw_info' do
    context 'when id_token is present' do
      let(:id_token) do
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSIsImdpdmVuX25hbWUiOiJKb2huIiwiZmFtaWx5X25hbWUiOiJEb2UiLCJlbWFpbCI6ImpvaG4uZG9lQGV4YW1wbGUuY29tIn0.placeholder_signature'
      end
      let(:decoded_token) do
        [
          {
            'sub' => '12345',
            'given_name' => 'John',
            'family_name' => 'Doe',
            'email' => 'john.doe@example.com'
          },
          { 'typ' => 'JWT', 'alg' => 'HS256' }
        ]
      end

      before do
        allow(subject).to receive(:id_token).and_return(id_token)
        allow(JWT).to receive(:decode).with(id_token, nil, false).and_return(decoded_token)
      end

      it 'decodes the JWT token' do
        result = subject.send(:raw_info)
        expect(result['sub']).to eq('12345')
        expect(result['given_name']).to eq('John')
        expect(result['family_name']).to eq('Doe')
        expect(result['email']).to eq('john.doe@example.com')
      end
    end

    context 'when id_token is nil' do
      before do
        allow(subject).to receive(:id_token).and_return(nil)
      end

      it 'returns empty user info' do
        result = subject.send(:raw_info)
        expect(result).to include(
          'given_name' => '',
          'family_name' => '',
          'email' => ''
        )
      end
    end
  end

  describe '#id_token' do
    let(:access_token_hash) { { 'id_token' => 'sample.jwt.token' } }

    before do
      allow(access_token).to receive(:[]).with('id_token').and_return('sample.jwt.token')
    end

    it 'returns the id_token from access_token' do
      expect(subject.send(:id_token)).to eq('sample.jwt.token')
    end
  end

  describe '#callback_url' do
    context 'when redirect_uri option is set' do
      before do
        subject.options[:redirect_uri] = 'https://example.com/custom/callback'
      end

      it 'returns the custom redirect_uri' do
        expect(subject.callback_url).to eq('https://example.com/custom/callback')
      end
    end

    context 'when redirect_uri option is not set' do
      before do
        allow(subject).to receive(:full_host).and_return('https://example.com')
        allow(subject).to receive(:callback_path).and_return('/auth/trimble_oauth2/callback')
      end

      it 'constructs callback url from full_host and callback_path' do
        expect(subject.callback_url).to eq('https://example.com/auth/trimble_oauth2/callback')
      end
    end
  end

  describe '#authorize_params' do
    it 'responds to authorize_params method' do
      expect(subject).to respond_to(:authorize_params)
    end
  end
end
