package com.homeofcode.https;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

public class DelimitedInputStream {
    final private InputStream is;
    final private byte[] delimiter;
    /**
     * this is the pi function from the COMPUTE-PREFIX-FUNCTION in "Introductions to Algorithms, 3rd Edition
     */
    private int[] pi;
    private KMPInputStream currentStream;
    private boolean EOFSeen;

    public DelimitedInputStream(InputStream is, byte[] delimiter) {
        this.is = is;
        this.delimiter = delimiter;

        computePrefixFunction();
    }

    /* COMPUTE-PREFIX-FUNCTION adjusted to base 0 */
    private void computePrefixFunction() {
        pi = new int[delimiter.length];
        int k = 0;
        pi[0] = 0;
        for (var q = 1; q < delimiter.length; q++) {
            while (k > 0 && delimiter[k] != delimiter[q]) k = pi[k-1];
            if (delimiter[k] == delimiter[q]) k = k + 1;
            pi[q] = k;
        }
    }

    public boolean hasMore() {
        return !EOFSeen;
    }

    /**
     * returns a stream to the bytes immediately following a boundary. the next InputStream cannot be obtained until
     * the previous one has been complete read.
     *
     * @return the InputStream to the next part
     * @throws IOException  if the previous stream has not been completely read.
     * @throws EOFException if the original InputStream is out of bytes.
     */
    public InputStream nextInputStream() throws IOException {
        if (currentStream != null && !currentStream.EOF) throw new IOException("Previous stream not finished");
        if (EOFSeen) throw new EOFException();
        return currentStream = new KMPInputStream();
    }

    private class KMPInputStream extends InputStream {
        final private byte[] pushedBack = new byte[delimiter.length];
        private boolean EOF = false;
        /**
         * this is q from KMP-MATCHER
         */
        private int matchCount = 0;
        private int pushedCount = 0;
        private int pushedOffset = 0;

        public int read() throws IOException {
            /*
             * 1) any characters in the pushback buffer need to be returned first.
             * 2) read the next character checking for EOF.
             * 3) if we can't grow the match, backup (by pushing previously matched characters) until we can or we
             *    aren't matching anything.
             * 4) if we match, we grow the match and then loop back to step 1) in case there are characters in the
             *    pushback and to do the next read.
             * 5) if pushback is empty we can return the current character.
             * 6) otherwise, push the current character to the end and return the first pushed back character.
             */
            while (true) {
                if (pushedCount > 0) {
                    return charFromPushback();
                } else {
                    int c = readCharCheckingEOF();
                    if (c == -1) {
                        if (matchCount > 0) pushPartialMatches();
                        return pushedCount > 0 ? charFromPushback() : -1;
                    }
                    while (matchCount > 0 && delimiter[matchCount] != c) {
                        pushPartialMatches();
                    }
                    if (delimiter[matchCount] == c) {
                        matchCount++;
                        // if we've matched everything, return EOF
                        if (matchCount == delimiter.length) {
                            EOF = true;
                            matchCount = 0;
                            return -1;
                        }
                        // we are going to go around the loop again since we need to check the pushback buffer before
                        // we try to read the next character
                    } else if (pushedCount == 0) {
                        return c;
                    } else {
                        pushedBack[pushedCount++] = (byte) c;
                        return charFromPushback();
                    }
                }
            }
        }

        private void pushPartialMatches() {
            for (int i = 0; i < matchCount - pi[matchCount-1]; i++) {
                pushedBack[pushedCount++] = delimiter[i];
            }
            matchCount = pi[matchCount-1];
        }

        private byte charFromPushback() {
            var c = pushedBack[pushedOffset++];
            if (pushedCount == pushedOffset) pushedCount = pushedOffset = 0;
            return c;
        }

        private Integer readCharCheckingEOF() throws IOException {
            if (EOF) return -1;
            var c = is.read();
            if (c == -1) {
                this.EOF = true;
                DelimitedInputStream.this.EOFSeen = true;
            }
            return c;
        }
    }

}
