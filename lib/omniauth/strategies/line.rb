require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Line < OmniAuth::Strategies::OAuth2

      option :name, 'line'
      option :client_options, {
               :site => 'https://access.line.me',
               :authorize_url => '/dialog/oauth/weblogin',
               :token_url => '/v1/oauth/accessToken'
             }

      def callback_phase
        options[:client_options][:site] = 'https://api.line.me'
        super
      end

      uid { raw_info['mid'] }

      info do
        prune!(
          { :display_name   => raw_info['displayName'],
            :picture_url    => raw_info['pictureUrl'],
            :status_message => raw_info['statusMessage'],
          }
        )
      end

      extra do
        hash = {}
        hash[:raw_info] = raw_info unless skip_info?
        prune! hash
      end

      def raw_info
        @raw_info ||= access_token.get('https://api.line.me/v1/profile').parsed
      end

      def prune!(hash)
        hash.delete_if do |_, value|
          prune!(value) if value.is_a?(Hash)
          value.nil? || (value.respond_to?(:empty?) && value.empty?)
        end
      end

      def callback_url
        full_host + script_name + callback_path
      end

    end
  end
end
