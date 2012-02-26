require "base64"
require "socket"
require "uri"
require "digest/md5"
require "digest/sha1"
require "openssl"
require "stringio"
require "logger"

# implement a websocket client that speaks the hybi-10 protocol
module Websocker
  class Client
    class NotConnectedError < RuntimeError; end
    class HandshakeNegotiationError < RuntimeError; end

    def initialize(opts = {})
      @host = opts[:host]
      @port = opts[:port] || 80
      @origin = opts[:origin] || "localhost"
      @path = opts[:path] || "/"
      @connected = false
      @logger = opts[:logger] || Logger.new(STDOUT)
      @logger.debug "Connecting to #{@host}:#{@port}"
    end

    def connect
      @sock = TCPSocket.open(@host, @port)
      @connected = true
      key = generateKey
      @sock.write handshake(key)
      headers = read_headers
      received_key = headers['Sec-WebSocket-Accept']
      expected_key = expected_security_key_answer(key)
      raise HandshakeNegotiationError, 'Key Mismatch' unless received_key == expected_key
      @sock
    end

    def listen
      @loop = Thread.new do
        while @connected
          read_once
        end
      end
    end
    
    def read_once
      message = read
      return unless @connected
      @logger.debug "received: #{message}"
      @on_message.call(message) unless @on_message.nil?
    end

    def on_message(&blk)
      @on_message = blk
    end

    def on_closed(&blk)
      @on_closed = blk
    end

    def send(data)
      byte1 = 0x80 | 1
      write_byte(byte1)

      # write length
      length = data.size
      if length <= 125
        byte2 = length
        write_byte(byte2)
      elsif length <= 65535
        byte2 = 126
        write_byte(byte2)
        # write length in next two bytes
        @sock.write [length].pack('n') # 16-bit unsigned
      else
        byte2 = 127
        write_byte(byte2)
        # write length in next eight bytes
        @sock.write [length].pack('Q') # 64-bit unsigned
      end
      @sock.write(data)
      @sock.flush
    end

    def close
      @logger.debug "Connection closed"
      @connected = false
      @on_closed.call unless @on_closed.nil?
    end

    private

    def handshake(key)
      hello = "GET #{@path} HTTP/1.1\r\n"
      hello << "Host: #{@host}\r\n"
      hello << "Upgrade: websocket\r\n"
      hello << "Connection: Upgrade\r\n"
      hello << "Sec-WebSocket-Version: 13\r\n"
      hello << "Sec-WebSocket-Key: #{key}\r\n"
      hello << "Sec-WebSocket-Origin: #{@origin}\r\n"
      hello << "\r\n"
    end

    def read_headers
      line = @sock.gets
      @logger.debug line
      headers = {}
      while line = @sock.gets
        line = line.chomp
        @logger.debug line
        break if line.empty?
        raise HandshakeNegotiationError unless line =~ /(\S+): (.*)/n
        headers[$1.to_s] = $2
      end
      headers
    end

    def expected_security_key_answer(key)
      Base64.encode64(Digest::SHA1.digest("#{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11")).gsub(/\n/, "")
    end

    def generateKey
      Base64.encode64((0..16).map { rand(255).chr } .join).strip
    end

    def read(buffer = '')
      fin, opcode, mask, len, masking_key, payload = read_frame

      @logger.debug "Read: opcode: #{opcode}: #{payload}"

      if opcode == 0x8 # connection closed
        close
      else
        if fin then
          return buffer + payload
        else
          return read(buffer + payload)
        end
      end
    end

    # write an unsigned byte
    def write_byte(byte)
      @sock.write [byte].pack("C")
    end

    # fin: 1 bit, indicates this is the final fragment in a message
    # rsv1, rsv2, rsv3: 1 bit, reserved, usually zero unless used by websocket extensions
    # opcode: 4 bits; 0 continuation, 1 text, 2 bin, 8 closed
    # mask: 1 bit, indicates payload is masked
    # len: 7 bits, payload length, may also use next 2 bytes if len==126, or next 8 bytes if len==127
    # payload: variable
    def read_frame
      byte = read_and_unpack_byte
      fin = (byte & 0b10000000) == 0b10000000
      rsv1 = byte & 0b01000000
      rsv2 = byte & 0b00100000
      rsv3 = byte & 0b00010000
      opcode = byte & 0b00001111

      @logger.debug "unexpected value: rsv1: #{rsv1}" unless rsv1 == 0
      @logger.debug "unexpected value: rsv2: #{rsv2}" unless rsv2 == 0
      @logger.debug "unexpected value: rsv3: #{rsv3}" unless rsv3 == 0

      byte = read_and_unpack_byte
      mask = (byte & 0b10000000) == 0b10000000
      lenflag = byte & 0b01111111

      # if len <= 125, this is the length
      # if len == 126, length is encoded on next two bytes
      # if len == 127, length is encoded on next eight bytes
      len = case lenflag
      when 126 # 2 bytes
        bytes = @sock.read(2)
        len = bytes.unpack("n")[0]
      when 127 # 8 bytes
        bytes = @sock.read(8)
        len = bytes.unpack("Q")[0]
      else
        lenflag
      end

      if mask then
        @logger.debug mask
        masking_key = @sock.read(4).unpack("C*")
      end

      payload = @sock.read(len)
      payload = apply_mask(payload, masking_key) if mask

      return fin, opcode, mask, len, masking_key, payload
    end

    def apply_mask(payload, masking_key)
      bytes = payload.unpack("C*")
      converted = []
      bytes.each_with_index do |b,i|
        converted.push(b ^ masking_key[i%4])
      end
      return converted.pack("C*")
    end

    # reads a byte and returns an 8-bit unsigned integer
    def read_and_unpack_byte
      byte = @sock.read(1)
      raise NotConnectedError if byte.nil?
      byte = byte.unpack('C')[0] unless byte.nil?
    end
  end
end
