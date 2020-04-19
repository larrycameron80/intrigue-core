module Intrigue
module Entity
class NetworkService < Intrigue::Model::Entity

  def self.metadata
    {
      :name => "NetworkService",
      :description => "A Generic Network Service",
      :user_creatable => true,
      :example => "8.8.8.8:53/udp"
    }
  end

  def validate_entity
    name =~ /^[\d\.\:]+\:\d{1,5}\/(tcp|udp)$/
  end

  def transform!
    
    set_details({
      "ip_address" => name.split(":").first,
      "port" => name.split(":").last.split("/").first,
      "protocol" => name.split(":").last.split("/").last  
    })

  true
  end

  def detail_string
    "#{details["service"]}"
  end

  def enrichment_tasks
    ["enrich/network_service"]
  end

  def scoped?
    return true if self.seed
    return false if self.hidden
  true # otherwise just default to true
  end

end
end
end
