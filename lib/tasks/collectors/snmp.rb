module Intrigue
module Task
module Collectors
class Snmp < Intrigue::Task::BaseTask

  def self.metadata
    {
      :name => "collector/snmp",
      :pretty_name => "Collector - SNMP",
      :authors => ["jcran"],
      :description => "Collect Details from NetworkService of type SNMP",
      :references => [],
      :type => "collector",
      :passive => false,
      :allowed_types => ["NetworkService"],
      :example_entities => [
        {"type" => "NetworkService", "details" => {"name" => "10.0.0.1:161/udp"}}
      ],
      :allowed_options => [],
      :created_types => []
    }
  end

  def run
    _log "Collecting... SNMP service: #{_get_entity_name}"
    
    port = _get_entity_detail("port").to_i || 161
    protocol = _get_entity_detail("protocol") ||  "udp"
    ip_address = _get_entity_detail "ip_address"

    # TODO ... not yet implemented
    #banner = _open_and_read_from_udp_socket(ip_address, port)

    # Create a tempfile to store results
    temp_file = "#{Dir::tmpdir}/nmap_snmp_info_#{rand(100000000)}.xml"

    nmap_string = "nmap #{ip_address} -sU -p #{port} --script=snmp-info -oX #{temp_file}"
    nmap_string = "sudo #{nmap_string}" unless Process.uid == 0

    _log "Running... #{nmap_string}"
    nmap_output = _unsafe_system nmap_string

    # parse the file and get output, setting it in details
    doc = File.open(temp_file) { |f| Nokogiri::XML(f) }

    service_doc = doc.xpath("//service")
    begin
      if service_doc && service_doc.attr("product")
        snmp_product = service_doc.attr("product").text
      end
    rescue NoMethodError => e
      _log_error "Unable to find attribute: product"
    end

    begin
      script_doc = doc.xpath("//script")
      if script_doc && script_doc.attr("output")
        script_output = script_doc.attr("output").text
      end
    rescue NoMethodError => e
      _log_error "Unable to find attribute: output"
    end

    out = {
      "product" => snmp_product,
      "output" => script_output
    }
    _log "Got SNMP details:#{out}"
    _set_entity_detail("collect", out )

    # cleanup
    begin
      File.delete(temp_file)
    rescue Errno::EPERM
      _log_error "Unable to delete file"
    end
  end

end
end
end
end