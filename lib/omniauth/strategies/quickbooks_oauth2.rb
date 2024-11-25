require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class QuickbooksOauth2 < OmniAuth::Strategies::OAuth2
      option :name, :quickbooks_oauth2

      option(
        :client_options,
        site: 'https://appcenter.intuit.com/connect/oauth2',
        authorize_url: 'https://appcenter.intuit.com/connect/oauth2',
        token_url: 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer'
      )

      uid { realm_id }

      info do
        {
          name: "#{raw_info[:given_name]} #{raw_info[:family_name]}",
          email: raw_info[:email_verified] ? raw_info[:email] : nil,
          shop_name: extra_info[:company_info][:company_name],
          country: extra_info[:company_info][:country],
          first_name: raw_info[:given_name],
          last_name: raw_info[:family_name],
          phone: raw_info[:phone_number_verified] ? raw_info[:phoneNumber] : nil,
        }
      end

      extra do
        {
          raw_info: raw_info,
          extra_info: extra_info,
        }
      end

      def raw_info
        @raw_info ||= scope?("openid") ? api_call(openid_endpoint) : {}
      end

      def extra_info
        @extra_info ||= scope?("com.intuit.quickbooks.accounting") ? api_call(company_info_endpoint) : {}
      end

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      private

      def scope?(scope)
        options.scope.split(/\s+/).include?(scope)
      end

      def accounts_domain
        "#{sandbox_prefix}accounts.platform.intuit.com"
      end

      def api_domain
        "#{sandbox_prefix}quickbooks.api.intuit.com"
      end

      def sandbox_prefix
        options.sandbox ? "sandbox-" : ""
      end

      def realm_id
        @realm_id ||= request.params["realmId"]
      end

      def openid_endpoint
        "https://#{accounts_domain}/v1/openid_connect/userinfo"
      end

      def company_info_endpoint
        "https://#{api_domain}/v3/company/#{realm_id}/companyinfo/#{realm_id}"
      end

      def api_call(url)
        deep_symbolize(access_token.get(url, headers: headers).parsed)
      end

      def headers
        { "Accept" => "application/json" }
      end
    end
  end
end