module Intrigue
module Task
module Enrich
class NetworkService < Intrigue::Task::BaseTask

  def self.metadata
    {
      :name => "enrich/network_service",
      :pretty_name => "Enrich Network Service",
      :authors => ["jcran"],
      :description => "Fills in details for a Network Service",
      :references => [],
      :type => "enrichment",
      :passive => false,
      :allowed_types => ["NetworkService"],
      :example_entities => [
        { "type" => "NetworkService",
          "details" => {
            "ip_address" => "1.1.1.1",
            "port" => 1111,
            "protocol" => "tcp"
          }
        }
      ],
      :allowed_options => [],
      :created_types => []
    }
  end

  ## Default method, subclasses must override this
  def run
    ename = _get_entity_name
    _log "Enriching... Network Service: #{ename}"

    # format it from a string like 1.1.1.1:80/tcp
    #unless _get_entity_detail("ip_address")
    #  _set_entity_detail("ip_address", ename.split(":").first) 
    #  _set_entity_detail("port", ename.split(":").last.split("/").first) 
    #  _set_entity_detail("protocol", ename.split(":").last.split("/").last) 
    #end

    # always try http 
    #enrich_http 
    #enrich_ftp if _get_entity_detail("service") == "FTP"
    #enrich_snmp if _get_entity_detail("service") == "SNMP"

  end

end
end
end
end