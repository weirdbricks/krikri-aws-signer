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
        io << kept.map { |segment| encode(decode(segment)) }.join('/')
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
      pairs.map { |key, value| "#{key}=#{value}" }.join('&')
    end

    # Trimall of a single header value line: whitespace runs collapse to one
    # space and leading/trailing whitespace is dropped.
    def trim_all(value : String) : String
      value.split.join(' ')
    end

    # Canonical value of one header occurrence: multi-line (folded) values
    # contribute one Trimall'd, comma-joined component per non-empty line.
    def header_value(raw : String) : String
      raw.split('\n').compact_map do |line|
        trimmed = trim_all(line)
        trimmed unless trimmed.empty?
      end.join(',')
    end

    # Canonical headers block and signed-headers list for the given headers,
    # skipping any header in *exclude* (case-insensitive). Returns
    # `{canonical_headers, signed_headers}` where *canonical_headers* has no
    # trailing newline.
    def headers(headers : HTTP::Headers, exclude : Enumerable(String) = ["authorization"]) : {String, String}
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
        names.each do |name|
          components = values_by_name[name].flat_map do |raw|
            raw.split('\n').compact_map do |line|
              trimmed = trim_all(line)
              trimmed unless trimmed.empty?
            end
          end
          io << name << ':' << components.join(',') << '\n'
        end
      end

      {canonical.chomp, names.join(';')}
    end

    # The canonical request itself. *path* and *query* are taken from the raw
    # request target: *path* in decoded form, *query* in wire form.
    def request(method : String, path : String, query : String, headers : HTTP::Headers,
                payload_hash : String, exclude : Enumerable(String) = ["authorization"]) : String
      canonical_headers, signed_headers = self.headers(headers, exclude)
      String.build do |io|
        io << method.upcase << '\n'
        io << self.path(path) << '\n'
        io << self.query(query) << '\n'
        io << canonical_headers << "\n\n"
        io << signed_headers << '\n'
        io << payload_hash
      end
    end

    # Percent-encode per RFC 3986: only `A-Za-z0-9-._~` (and `/` when
    # *keep_slash*) are kept literal.
    def encode(value : String, keep_slash : Bool = false) : String
      String.build do |io|
        value.each_byte do |byte|
          if unreserved?(byte) || (keep_slash && byte == '/'.ord)
            io.write_byte(byte)
          else
            io << '%'
            io << byte.to_s(16).upcase.rjust(2, '0')
          end
        end
      end
    end

    # Strict percent-decoding: `%XX` escapes become bytes, anything else
    # (including stray `%` and literal `+`) is kept as data.
    def decode(value : String) : String
      return value unless value.includes?('%')
      String.build do |io|
        bytes = value.to_slice
        cursor = 0
        while cursor < bytes.size
          byte = bytes[cursor]
          if byte == '%'.ord && cursor + 2 < bytes.size
            high = hex_value(bytes[cursor + 1])
            low = hex_value(bytes[cursor + 2])
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

    private def unreserved?(byte : UInt8) : Bool
      (byte >= 'a'.ord && byte <= 'z'.ord) ||
        (byte >= 'A'.ord && byte <= 'Z'.ord) ||
        (byte >= '0'.ord && byte <= '9'.ord) ||
        byte == '-'.ord || byte == '.'.ord || byte == '_'.ord || byte == '~'.ord
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
