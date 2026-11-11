module KrikriAwsSigner
  # Canonicalization of request components, per "Task 1: Create a canonical
  # request" of the Signature Version 4 signing process.
  #
  # The normalization rules are the ones AWS's own tooling applies (and that
  # the public SigV4 test-suite vectors pin down):
  #
  # * Paths are normalized like `botocore.utils.remove_dot_segments`:
  #   dot segments are removed and empty segments collapse, so `//example//`
  #   becomes `/example/` and `/example/..` becomes `/`. Each remaining
  #   segment is strict-percent-decoded and then re-encoded per RFC 3986
  #   (everything except `A-Za-z0-9-._~`), so both decoded and wire-form
  #   paths canonicalize to the same encoded URI.
  # * Query strings are parsed from the wire form: components are split on
  #   `&` and the first `=`, each side is percent-decoded and then re-encoded
  #   per RFC 3986 (only `A-Za-z0-9-._~` kept literal), and the pairs are
  #   sorted by encoded key, then encoded value. A raw `+` is a literal plus
  #   (`%2B` when encoded), not a space.
  # * Header values are Trimall'd: runs of whitespace collapse to a single
  #   space. Folded/multi-line values (and duplicate header names) contribute
  #   one comma-separated component each, in the order they appear.
  module Canonical
    extend self

    # Canonical URI for the given path (decoded or wire form).
    def path(path : String) : String
      return "/" if path.empty?

      kept = [] of String
      path.split('/').each do |segment|
        next if segment.empty? || segment == "."
        if segment == ".."
          kept.pop unless kept.empty?
        else
          kept << segment
        end
      end

      normalized = String.build do |io|
        io << '/' if path.starts_with?('/')
        first_segment = true
        kept.each do |segment|
          io << '/' unless first_segment
          encode_into(io, decode(segment))
          first_segment = false
        end
        io << '/' if path.ends_with?('/') && !kept.empty?
      end
      normalized.empty? ? "/" : normalized
    end

    # Canonical query string for a raw (wire-form) query string.
    def query(query : String) : String
      pairs = query.split('&').compact_map do |pair|
        next if pair.empty?
        key, _, value = pair.partition('=')
        {encode(decode(key)), encode(decode(value))}
      end
      pairs.sort!
      String.build do |io|
        first_pair = true
        pairs.each do |key, value|
          io << '&' unless first_pair
          io << key << '=' << value
          first_pair = false
        end
      end
    end

    # Trimall of a single header value line: whitespace runs collapse to one
    # space and leading/trailing whitespace is dropped. Values that are already
    # clean (no leading/trailing whitespace, no whitespace runs) are returned
    # as-is, without allocating.
    def trim_all(value : String) : String
      clean = true
      seen_content = false
      previous_was_space = false
      value.each_byte do |byte|
        if whitespace?(byte)
          clean = false if previous_was_space || !seen_content
          previous_was_space = true
        else
          seen_content = true
          previous_was_space = false
        end
      end
      clean = false if previous_was_space
      return value if clean

      String.build do |io|
        emitted = false
        space_pending = false
        value.each_byte do |byte|
          if whitespace?(byte)
            space_pending = true
          else
            io.write_byte(' '.ord.to_u8) if space_pending && emitted
            io.write_byte(byte)
            emitted = true
            space_pending = false
          end
        end
      end
    end

    # Canonical value of one header occurrence: multi-line (folded) values
    # contribute one Trimall'd, comma-joined component per non-empty line.
    def header_value(raw : String) : String
      String.build do |io|
        first_component = true
        raw.split('\n').each do |line|
          trimmed = trim_all(line)
          next if trimmed.empty?
          io << ',' unless first_component
          io << trimmed
          first_component = false
        end
      end
    end

    # Headers excluded from signing by default.
    DEFAULT_EXCLUDE = ["authorization"]

    # Canonical headers block and signed-headers list for the given headers,
    # skipping any header in *exclude* (case-insensitive). Returns
    # `{canonical_headers, signed_headers}` where *canonical_headers* has no
    # trailing newline.
    def headers(headers : HTTP::Headers, exclude : Enumerable(String) = DEFAULT_EXCLUDE) : {String, String}
      excluded = exclude.map(&.downcase)
      values_by_name = {} of String => Array(String)
      headers.each do |key, values|
        name = key.to_s.downcase
        next if excluded.includes?(name)
        list = values_by_name[name] ||= [] of String
        values.each { |value| list << value }
      end
      names = values_by_name.keys.sort!

      canonical = String.build do |io|
        first_header = true
        names.each do |name|
          io << '\n' unless first_header
          first_header = false
          io << name << ':'
          first_component = true
          values_by_name[name].each do |raw|
            if raw.includes?('\n')
              raw.split('\n').each do |line|
                trimmed = trim_all(line)
                next if trimmed.empty?
                io << ',' unless first_component
                io << trimmed
                first_component = false
              end
            else
              trimmed = trim_all(raw)
              next if trimmed.empty?
              io << ',' unless first_component
              io << trimmed
              first_component = false
            end
          end
        end
      end

      {canonical, names.join(';')}
    end

    # The canonical request itself. *path* and *query* are taken from the raw
    # request target: *path* in decoded form, *query* in wire form.
    def request(method : String, path : String, query : String, headers : HTTP::Headers,
                payload_hash : String, exclude : Enumerable(String) = DEFAULT_EXCLUDE) : String
      canonical_headers, signed_headers = self.headers(headers, exclude)
      request(method, path, query, {canonical_headers, signed_headers}, payload_hash)
    end

    # The canonical request for a precomputed canonical-headers block and
    # signed-headers list (as returned by `.headers`); lets a caller use the
    # pair once instead of canonicalizing the headers twice.
    def request(method : String, path : String, query : String,
                canonical_headers : {String, String}, payload_hash : String) : String
      String.build do |io|
        io << method.upcase << '\n'
        io << self.path(path) << '\n'
        io << self.query(query) << '\n'
        io << canonical_headers[0] << "\n\n"
        io << canonical_headers[1] << '\n'
        io << payload_hash
      end
    end

    # Percent-encode per RFC 3986: only `A-Za-z0-9-._~` are kept literal.
    # Values that need no escaping are returned as-is, without allocating.
    def encode(value : String) : String
      return value unless value.each_byte.any? { |byte| !unreserved?(byte) }
      String.build { |io| encode_into(io, value) }
    end

    # Percent-encode per RFC 3986 into *io* (only `A-Za-z0-9-._~` literal).
    def encode_into(io : IO, value : String) : Nil
      value.each_byte do |byte|
        if unreserved?(byte)
          io.write_byte(byte)
        else
          io.write_byte('%'.ord.to_u8)
          io.write_byte(HEX_DIGITS[byte >> 4])
          io.write_byte(HEX_DIGITS[byte & 0x0F])
        end
      end
    end

    # Strict percent-decoding: `%XX` escapes become bytes, anything else
    # (including stray `%` and literal `+`) is kept as data.
    def decode(value : String) : String
      return value unless value.includes?('%')
      String.build do |io|
        size = value.bytesize
        cursor = 0
        while cursor < size
          byte = value.byte_at(cursor)
          if byte == '%'.ord && cursor + 2 < size
            high = hex_value(value.byte_at(cursor + 1))
            low = hex_value(value.byte_at(cursor + 2))
            if high < 16 && low < 16
              io.write_byte((high << 4) | low)
              cursor += 3
              next
            end
          end
          io.write_byte(byte)
          cursor += 1
        end
      end
    end

    HEX_DIGITS = "0123456789ABCDEF".to_slice

    private def unreserved?(byte : UInt8) : Bool
      (byte >= 'a'.ord && byte <= 'z'.ord) ||
        (byte >= 'A'.ord && byte <= 'Z'.ord) ||
        (byte >= '0'.ord && byte <= '9'.ord) ||
        byte == '-'.ord || byte == '.'.ord || byte == '_'.ord || byte == '~'.ord
    end

    # Whether *byte* is ASCII whitespace, the set Crystal's `String#split`
    # (and thus the Trimall rule) collapses on.
    private def whitespace?(byte : UInt8) : Bool
      byte == ' '.ord || byte == '\t'.ord || byte == '\n'.ord ||
        byte == '\v'.ord || byte == '\f'.ord || byte == '\r'.ord
    end

    # Value of a hex digit; 16 marks a non-hex byte.
    private def hex_value(byte : UInt8) : UInt8
      case byte
      when '0'.ord..'9'.ord then byte - '0'.ord
      when 'a'.ord..'f'.ord then byte - 'a'.ord + 10
      when 'A'.ord..'F'.ord then byte - 'A'.ord + 10
      else                       16_u8
      end
    end
  end
end
