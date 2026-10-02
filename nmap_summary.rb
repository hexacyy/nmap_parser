#!/usr/bin/env ruby
# Parse an Nmap XML scan and print one summary line per live host.
# Usage: ruby nmap_summary.rb scan.xml

require 'rexml/document'

abort "Usage: #{$PROGRAM_NAME} <nmap.xml>" unless ARGV[0]

doc = REXML::Document.new(File.read(ARGV[0]))

doc.elements.each('nmaprun/host') do |host|
  next unless host.elements['status']&.attributes['state'] == 'up'

  ip = host.elements.each('address') { |a| break a if a.attributes['addrtype'] == 'ipv4' }
  ip = (ip.is_a?(REXML::Element) ? ip : host.elements['address'])&.attributes['addr']

  hostname = host.elements['hostnames/hostname']&.attributes['name']
  os = host.elements['os/osmatch']&.attributes['name']

  ports = host.get_elements('ports/port').select do |p|
    p.elements['state']&.attributes['state'] == 'open'
  end.map do |p|
    svc = p.elements['service']
    desc = [svc&.attributes['name'], svc&.attributes['product'], svc&.attributes['version']].compact.join(' ')
    "#{p.attributes['portid']}/#{p.attributes['protocol']}:#{desc}"
  end

  fields = [ip, hostname, os, ports.join(', ')].compact.reject(&:empty?)
  puts fields.join(' | ')
end
