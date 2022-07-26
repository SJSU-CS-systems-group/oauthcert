package com.homeofcode.https;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;

/**
 * Parse MultiPartFromData from HTTP clients. This is totally not to spec, but we are going to pull the delimiter from
 * the first line of input.
 *
 * This class is not threadsafe.
 */
public class MultiPartFormDataParser {
    // RFC 2046 spec says that boundary can have at most 70 characters and not whitespace
    //                    that boundary starts with two dashes --
    //                    that the closing boundary has two dashes -- at the end
    //                    that the CRLF the proceeds the boundary is considered part of the boundary
    // RFC 7578 refers to RFC 2046 for the boundary rules
    final DelimitedInputStream dis;
    private boolean EOC = false; // set to true when we see closing delimiter

    public MultiPartFormDataParser(InputStream is) throws IOException {
        // if we add "\r\n" to the delimiter, it will terminate perfectly the InputStreams
        this.dis = new DelimitedInputStream(is, ("\r\n" + readLine(is)).getBytes());
    }

    public static class FormField extends HashMap<String, String> {
        public InputStream is;
    }

    static private String readLine(InputStream is) throws IOException {
        var baos = new ByteArrayOutputStream();
        int c;
        while ((c = is.read()) != -1 && c != '\n') {
            baos.write((byte)c);
        }
        var bytes = baos.toByteArray();
        var len = bytes.length;
        if (bytes[len-1] == (byte)'\r') len--;
        return new String(bytes, 0, len);
    }

    /**
     * Return headers for next part of InputStream.
     *
     * @return map of headers or null if at end of content.
     * @throws IOException if there is a problem reading the underlying stream
     */
    public FormField nextField() throws IOException {
        if (EOC) return null;

        var is = dis.nextInputStream();
        if (is == null) {
            EOC = true;
            return null;
        }

        FormField ff = new FormField();
        ff.is = is;
        String line;
        while ((line = readLine(is)).length() > 0) {
            if (line.equals("--")) {
                EOC = true;
                return null;
            }
            var parts = line.split(":");
            ff.put(parts[0], parts[1].trim());
        }

        return ff;
    }
}
