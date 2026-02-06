# frozen_string_literal: true

require 'omniauth-oauth2'
require 'jwt'
require 'net/http'
require 'json'

module OmniAuth
  module Strategies
    class TrimbleOauth2 < OmniAuth::Strategies::OAuth2
      TRIMBLE_ISSUER = 'https://id.trimble.com'
      JWKS_CACHE_LIFETIME = 300 # seconds

      option :name, :trimble_oauth2

      option :authorize_options, %i[scope]

      option :client_options, {
        site: TRIMBLE_ISSUER,
        authorize_url: '/oauth/authorize',
        token_url: '/oauth/token'
      }

      option :response_type, 'code'
      option :jwks_uri, "#{TRIMBLE_ISSUER}/.well-known/jwks.json"
      option :issuer, TRIMBLE_ISSUER
      option :jwt_leeway, 10

      uid { raw_info['sub'] }

      info do
        {
          name: [raw_info['given_name'], raw_info['family_name']].compact.join(' '),
          email: raw_info['email'],
          first_name: raw_info['given_name'],
          last_name: raw_info['family_name']
        }
      end

      extra do
        {
          raw_info: raw_info,
          location: raw_info['data_region'],
          picture: raw_info['picture']
        }
      end

      def callback_url
        full_host + callback_path
      end

      def raw_info
        @raw_info ||= if id_token.nil?
                        {}
                      else
                        JWT.decode(id_token, nil, true, decode_options)[0]
                      end
      end

      private

      def decode_options
        {
          algorithms: ['RS256'],
          jwks: jwks_loader,
          iss: options[:issuer],
          verify_iss: true,
          verify_expiration: true,
          exp_leeway: options[:jwt_leeway],
          verify_iat: true,
          required_claims: %w[exp iss sub]
        }
      end

      def jwks_loader
        lambda do |jwt_options|
          if jwks_cache_expired? || jwt_options[:kid_not_found]
            refresh_jwks_cache
          end
          @jwks_cache[:keys]
        end
      end

      def jwks_cache_expired?
        @jwks_cache.nil? || @jwks_cache[:fetched_at] < Time.now.to_i - JWKS_CACHE_LIFETIME
      end

      def refresh_jwks_cache
        @jwks_cache = {
          keys: fetch_jwks,
          fetched_at: Time.now.to_i
        }
      end

      def fetch_jwks
        uri = URI(options[:jwks_uri])
        http = Net::HTTP.new(uri.host, uri.port)
        if uri.scheme == 'https'
          http.use_ssl = true
          http.verify_mode = OpenSSL::SSL::VERIFY_PEER
          store = OpenSSL::X509::Store.new
          store.set_default_paths
          http.cert_store = store
        end

        response = http.request(Net::HTTP::Get.new(uri.request_uri))

        unless response.is_a?(Net::HTTPSuccess)
          raise "JWKS fetch returned HTTP #{response.code}"
        end

        JSON.parse(response.body)
      end

      def id_token
        @id_token ||= access_token['id_token']
      end
    end
  end
end
