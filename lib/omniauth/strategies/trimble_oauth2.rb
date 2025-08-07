# frozen_string_literal: true

require 'omniauth-oauth2'
require 'jwt'

module OmniAuth
  module Strategies
    class TrimbleOauth2 < OmniAuth::Strategies::OAuth2
      option :name, :trimble_oauth2

      option :authorize_options, %i[state redirect_uri scope]

      option :client_options, {
        site: 'https://id.trimble.com',
        authorize_url: '/oauth/authorize',
        token_url: '/oauth/token'
      }

      option :response_type, 'code'

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
        options[:redirect_uri] || (full_host + callback_path)
      end

Vj
        if id_token.nil?
          @raw_info = {
            given_name: '',
            family_name: '',
            email: ''
          }
        else
          decoded_info = JWT.decode(id_token, nil, false)
          @raw_info ||= decoded_info[0]
        end
      end

      def authorize_params
        super.tap do |params|
          options[:authorize_options].each do |k|
            params[k] = request.params[k.to_s] unless [nil, ''].include?(request.params[k.to_s])
          end
        end
      end

      private

      def id_token
        @id_token ||= access_token['id_token']
      end
    end
  end
end
