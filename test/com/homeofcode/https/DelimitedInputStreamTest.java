package com.homeofcode.https;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Random;

class DelimitedInputStreamTest {
    @Test
    public void specialCases() throws IOException {
        var dis = new DelimitedInputStream(new ByteArrayInputStream("acaabaca".getBytes()), "ab".getBytes());
        var str1 = fullyRead(dis.nextInputStream());
        var str2 = fullyRead(dis.nextInputStream());
        Assertions.assertEquals("aca", str1);
        Assertions.assertEquals("aca", str2);

        dis = new DelimitedInputStream(new ByteArrayInputStream("acaaabaaca".getBytes()), "aaba".getBytes());
        str1 = fullyRead(dis.nextInputStream());
        str2 = fullyRead(dis.nextInputStream());
        Assertions.assertEquals("aca", str1);
        Assertions.assertEquals("aca", str2);
    }

    private static String fullyRead(InputStream is) throws IOException {
        var baos = new ByteArrayOutputStream();
        is.transferTo(baos);
        return baos.toString();
    }

    @ParameterizedTest
    @ValueSource(ints =  {10, 100, 1_000, 100_000, 1_000_000, 10_000_000})
    public void randomStreams(int fragmentSize) throws IOException {
        var rand = new Random();
        var delim = new ByteArrayOutputStream();
        for (int i = 0; i < 9; i++) {
            delim.write(rand.nextInt(5) + 'A');
        }
        var de = delim.toByteArray();
        var data = new ByteArrayOutputStream();
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < fragmentSize + i; j++) {
                data.write(rand.nextInt(5) + 'A');
            }
            data.write(de);
        }

        var da = data.toByteArray();
        var dastr = new String(da);
        var destr = new String(de);
        var parts = dastr.split(destr);
        System.out.printf("Found %d parts\n", parts.length);

        DelimitedInputStream dis = new DelimitedInputStream(new ByteArrayInputStream(da), de);
        var found = new ArrayList<String>();
        while (dis.hasMore()) {
            StringBuilder sb = new StringBuilder();
            try (var is = dis.nextInputStream()) {
                int c;
                while ((c = is.read()) != -1) sb.append((char) c);
            }
            found.add(sb.toString());
        }

        for (int i = 0; i < parts.length; i++) {
            Assertions.assertEquals(parts[i], found.get(i));
        }
    }
}