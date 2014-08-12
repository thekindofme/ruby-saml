require "xml_security"
require "time"
require "base64"
require "zlib"

module OneLogin
  module RubySaml
    class Logoutresponse

      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
      PROTOCOL  = "urn:oasis:names:tc:SAML:2.0:protocol"

      # For API compability, this is mutable.
      attr_accessor :settings

      attr_reader :document
      attr_reader :response
      attr_reader :options

      #
      # In order to validate that the response matches a given request, append
      # the option:
      #   :matches_request_id => REQUEST_ID
      #
      # It will validate that the logout response matches the ID of the request.
      # You can also do this yourself through the in_response_to accessor.
      #
      def initialize(response, settings = nil, options = {})
        raise ArgumentError.new("Logoutresponse cannot be nil") if response.nil?
        self.settings = settings

        @options = options
        @response = decode_raw_response(response)
        @document = XMLSecurity::SignedDocument.new(response)
      end

      # Create a LogoutResponse to to the IdP's LogoutRequest
      #  (For IdP initiated SLO)
      def self.create( settings, params={}, options = {} )
        opt = { in_response_to: nil,
                status: "urn:oasis:names:tc:SAML:2.0:status:Success",
                extra_parameters: nil }.merge(options)
        return nil if opt[:in_response_to].nil?

        new_response = REXML::Document.new
        new_response.context[:attribute_quote] = :quote
        uuid = "_" + UUID.new.generate
        time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        root = new_response.add_element "samlp:LogoutResponse", { "xmlns:samlp" => PROTOCOL, "xmlns:saml" => ASSERTION }
        root.attributes['ID'] = uuid
        root.attributes['IssueInstant'] = time
        root.attributes['Destination'] = "#{opt[:destination]}"
        root.attributes['Version'] = "2.0"
        root.attributes['InResponseTo'] = opt[:in_response_to]

        if opt[:status]
          status = root.add_element "samlp:Status"
          status.add_element "samlp:StatusCode", {
              "Value" => opt[:status]
          }
        end
        if settings && settings.issuer
          issuer = root.add_element "saml:Issuer", {
              "xmlns:saml" => "urn:oasis:names:tc:SAML:2.0:assertion"
          }
          issuer.text = settings.issuer
        end
        #meta = Metadata.new( settings )
        Logging.debug "Created LogoutResponse:\n#{new_response}"
        #return meta.create_slo_response( new_response.to_s, opt[:extra_parameters] )

        #root.attributes['Destination'] = action

        text = ""
        new_response.write(text, 1)

        deflated_response  = Zlib::Deflate.deflate(text, 9)[2..-5]
        base64_response    = Base64.encode64(deflated_response)
        encoded_response   = CGI.escape(base64_response)

        target_url = options[:destination]
        params_prefix     = (target_url =~ /\?/) ? '&' : '?'
        response_params    = "#{params_prefix}SAMLResponse=#{encoded_response}"

        params.each_pair do |key, value|
          response_params << "&#{key}=#{CGI.escape(value.to_s)}"
        end

        target_url + response_params
      end

      # # function to return the created request as an XML document
      # def to_xml
      #   text = ""
      #   @response.write(text, 1)
      #   return text
      # end
      #
      # def to_s
      #   @response.to_s
      # end

      def validate!
        validate(false)
      end

      def validate(soft = true)
        return false unless valid_saml?(soft) && valid_state?(soft)

        valid_in_response_to?(soft) && valid_issuer?(soft) && success?(soft)
      end

      def success?(soft = true)
        unless status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
          return soft ? false : validation_error("Bad status code. Expected <urn:oasis:names:tc:SAML:2.0:status:Success>, but was: <#@status_code> ")
        end
        true
      end

      def in_response_to
        @in_response_to ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.attributes['InResponseTo']
        end
      end

      def issuer
        @issuer ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node ||= REXML::XPath.first(document, "/p:LogoutResponse/a:Assertion/a:Issuer", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.text
        end
      end

      def status_code
        @status_code ||= begin
          node = REXML::XPath.first(document, "/p:LogoutResponse/p:Status/p:StatusCode", { "p" => PROTOCOL, "a" => ASSERTION })
          node.nil? ? nil : node.attributes["Value"]
        end
      end

      private

      def decode(encoded)
        Base64.decode64(encoded)
      end

      def inflate(deflated)
        zlib = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        zlib.inflate(deflated)
      end

      def decode_raw_response(response)
        if response =~ /^</
          return response
        elsif (decoded  = decode(response)) =~ /^</
          return decoded
        elsif (inflated = inflate(decoded)) =~ /^</
          return inflated
        end

        raise "Couldn't decode SAMLResponse"
      end

      def valid_saml?(soft = true)
        Dir.chdir(File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'schemas'))) do
          @schema = Nokogiri::XML::Schema(IO.read('saml20protocol_schema.xsd'))
          @xml = Nokogiri::XML(self.document.to_s)
        end
        if soft
          @schema.validate(@xml).map{ return false }
        else
          @schema.validate(@xml).map{ |error| validation_error("#{error.message}\n\n#{@xml.to_s}") }
        end
      end

      def valid_state?(soft = true)
        if response.empty?
          return soft ? false : validation_error("Blank response")
        end

        if settings.nil?
          return soft ? false : validation_error("No settings on response")
        end

        if settings.issuer.nil?
          return soft ? false : validation_error("No issuer in settings")
        end

        if settings.idp_cert_fingerprint.nil? && settings.idp_cert.nil?
          return soft ? false : validation_error("No fingerprint or certificate on settings")
        end

        true
      end

      def valid_in_response_to?(soft = true)
        return true unless self.options.has_key? :matches_request_id

        unless self.options[:matches_request_id] == in_response_to
          return soft ? false : validation_error("Response does not match the request ID, expected: <#{self.options[:matches_request_id]}>, but was: <#{in_response_to}>")
        end

        true
      end

      def valid_issuer?(soft = true)
        unless URI.parse(issuer) == URI.parse(self.settings.issuer)
          return soft ? false : validation_error("Doesn't match the issuer, expected: <#{self.settings.issuer}>, but was: <#{issuer}>")
        end
        true
      end

      def validation_error(message)
        raise ValidationError.new(message)
      end
    end
  end
end
