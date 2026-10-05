#!/usr/bin/env ruby
# Parse an Nmap XML scan and print one tab-separated line per open port:
# ip  port  service  product  version  extrainfo
# Usage: ruby nmap_summary.rb scan.xml

require 'rexml/document'

abort "Usage: #{$PROGRAM_NAME} <nmap.xml>" unless ARGV[0]

# element.elements[path]&.attributes[name] is NOT nil-safe end-to-end:
# &. only guards the `.attributes` call, not the `[name]` after it.
# This helper guards the whole chain.
def attr(element, path, name)
  node = element.elements[path]
  node && node.attributes[name]
end

doc = REXML::Document.new(File.read(ARGV[0]))

doc.elements.each('nmaprun/host') do |host|
  next unless attr(host, 'status', 'state') == 'up'

  ipv4 = host.get_elements('address').find { |a| a.attributes['addrtype'] == 'ipv4' }
  ip = (ipv4 || host.elements['address'])&.attributes&.[]('addr')

  host.get_elements('ports/port').each do |p|
    next unless attr(p, 'state', 'state') == 'open'

    fields = [
      ip,
      p.attributes['portid'],
      attr(p, 'service', 'name'),
      attr(p, 'service', 'product'),
      attr(p, 'service', 'version'),
      attr(p, 'service', 'extrainfo')
    ]
    fields.pop while fields.last.nil?

    puts fields.map(&:to_s).join("\t")
  end
end
