package com.homeofcode.oauth.ovpn;

import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import picocli.CommandLine;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.Callable;

public class OVPNProfile {

    static int screenWidth = 80;
    static String authUrl;
    static String ovpnTemplate;

    public static void main(String[] args) {
        try {
            var authUrlStream = OVPNProfile.class.getResourceAsStream("/authUrl");
            if (authUrlStream == null) {
                throw new IOException("/authUrl missing from jar file.");
            }
            authUrl = new String(authUrlStream.readAllBytes()).trim();
            var ovpnTemplateStream = OVPNProfile.class.getResourceAsStream("/ovpnTemplate");
            if (ovpnTemplateStream == null) {
                throw new IOException("/ovpnTemplate missing from jar file.");
            }
            ovpnTemplate = new String(ovpnTemplateStream.readAllBytes());
        } catch (IOException e) {
            System.out.println(screenWidth);
            Cli.error("Internal error: " + e.getMessage());
            System.exit(2);
        }
        CommandLine commandLine = new CommandLine(new Cli());
        screenWidth = commandLine.getCommandSpec().usageMessage().autoWidth(true).width();
        if (screenWidth < 20) screenWidth = 80;
        System.exit(commandLine.execute(args));
    }

    @CommandLine.Command(name = "OVPNProfile", mixinStandardHelpOptions = true, description = "Generate an OVPNProfile from a template.")
    static class Cli implements Callable<Integer> {

        static {
            // make sure we don't miss any exceptions
            Thread.setDefaultUncaughtExceptionHandler((t, te) -> te.printStackTrace());
            System.setProperty("java.util.logging.SimpleFormatter.format", "%1$tF %1$tT %4$s %5$s%n");
        }

        @CommandLine.Parameters(index = "0", description = "email")
        private String email;
        @CommandLine.Option(names = "-p", description = "password for key.")
        private String password;

        @CommandLine.Option(names = "-d", description = "working directory for certificates and ovpn file.")
        private final File workingDirectory = new File(".");

        static void wrapOutput(String str) {
            var line = new CommandLine.Help.Column(screenWidth, 0, CommandLine.Help.Column.Overflow.WRAP);
            var txtTable = CommandLine.Help.TextTable.forColumns(
                    CommandLine.Help.defaultColorScheme(CommandLine.Help.Ansi.AUTO), line);
            txtTable.indentWrappedLines = 0;
            txtTable.addRowValues(str);
            System.out.print(txtTable);
            System.out.flush();
        }

        static void error(String message) {
            wrapOutput(CommandLine.Help.Ansi.AUTO.string("@|red " + message + "|@"));
        }

        static void info(String message) {
            wrapOutput(CommandLine.Help.Ansi.AUTO.string("@|blue " + message + "|@"));
        }

        @Override
        public Integer call()
                throws NoSuchAlgorithmException, OperatorCreationException, IOException, InterruptedException {

            /* validate all the parameters first */
            if (!workingDirectory.isDirectory()) {
                error(String.format("%s is not a valid working directory.", workingDirectory.getCanonicalPath()));
                System.exit(2);
            }
            var csrFile = new File(workingDirectory, String.format("%s.csr", email));
            var signedFile = new File(workingDirectory, String.format("%s.crt", email));
            if (signedFile.exists()) {
                if (!signedFile.delete()) {
                    error(String.format("Could not remove %s.", signedFile.getCanonicalPath()));
                    System.exit(2);
                } else {
                    info(String.format("Deleted %s.", signedFile.getCanonicalPath()));
                }
            }
            var ovpnFile = new File(workingDirectory, String.format("%s.ovpn", email));
            if (ovpnFile.exists()) {
                error(String.format("%s already exists.", ovpnFile.getCanonicalPath()));
                System.exit(2);
            }

            /* generate CSR */
            var gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            var pair = gen.generateKeyPair();
            Object privateKeyToEncode = pair.getPrivate();
            if (password != null) {
                var privEncryptor = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_3DES).setPassword(
                        password.toCharArray()).build();
                privateKeyToEncode = new JcaPKCS8Generator(pair.getPrivate(), privEncryptor);
            }
            var privPem = new StringWriter();
            try (var privPEMWriter = new JcaPEMWriter(privPem)) {
                privPEMWriter.writeObject(privateKeyToEncode);
            }
            var privPemString = privPem.toString();

            var csrSigner = new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate());
            var csr =
                    new JcaPKCS10CertificationRequestBuilder(new X500Principal("CN=" + email), pair.getPublic()).build(
                            csrSigner);
            var csrPem = new StringWriter();
            try (var csrPemWriter = new JcaPEMWriter(csrPem)) {
                csrPemWriter.writeObject(csr);
            }
            Files.writeString(csrFile.toPath(), csrPem.toString());
            info(String.format(
                    "Please go to %s and upload the file %s which was just generated. Download the CRT file to  %s.",
                    authUrl,
                    csrFile.getCanonicalPath(), signedFile.getCanonicalPath()));
            String waitingString = String.format("Waiting for %s  ", signedFile.getCanonicalPath());
            System.out.print(waitingString);
            var pattern = new char[]{'|', '/', '-', '\\', '|', '/', '-', '\\'};
            var patternIndex = 0;
            while (!signedFile.exists()) {
                System.out.printf("\b%c", pattern[patternIndex]);
                System.out.flush();
                patternIndex = (patternIndex + 1) % pattern.length;
                Thread.sleep(1000);
            }
            //System.out.print("\b".repeat(waitingString.length()+1));
            System.out.printf("\b\u2705\n");
            System.out.flush();
            Files.writeString(ovpnFile.toPath(),
                    ovpnTemplate.replace("SIGNEDCERT", Files.readString(signedFile.toPath()))
                            .replace("PRIVATEKEY", privPemString));
            info(String.format("Your OVPN profile is in %s", ovpnFile.getCanonicalPath()));
            return 0;
        }
    }
}
