module Intrigue
module Task
module Collectors
class Ftp < Intrigue::Task::BaseTask

  def self.metadata
    {
      :name => "collector/ftp",
      :pretty_name => "Collector - FTP",
      :authors => ["jcran"],
      :description => "Collect Details from NetworkService of type FTP",
      :references => [],
      :type => "collector",
      :passive => false,
      :allowed_types => ["NetworkService"],
      :example_entities => [
        {"type" => "NetworkService", "details" => {"name" => "10.0.0.1:21/tcp"}}
      ],
      :allowed_options => [],
      :created_types => []
    }
  end

  def run 
    _log "Collecting... FTP service: #{_get_entity_name}"
    
    # TODO this won't work once we fix the name regex
    ip_address = _get_entity_detail("ip_address")
    port = _get_entity_detail("port").to_i
    port = 21 if port == 0 # handle empty port
    protocol = _get_entity_detail("protocol") ||  "tcp"
    
    # Check to make sure we have a sane target
    if protocol.downcase == "tcp" && ip_address && port

      banner = _open_and_read_text_from_tcp_socket(ip_address, port)

      if banner && banner.length > 0
        _log "Got banner: #{banner}"
      else
        _log "No banner available"
      end

      _set_entity_detail "banner", banner
      _set_entity_detail "collect", {} # DO MORE STUFF HERE

    end
  end


  
end
end
end
end