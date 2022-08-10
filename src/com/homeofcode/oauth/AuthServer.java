package com.homeofcode.oauth;

import com.homeofcode.https.HttpPath;
import com.homeofcode.https.MultiPartFormDataParser;
import com.homeofcode.https.SimpleHttpsServer;
import com.sun.net.httpserver.HttpExchange;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.X509DefaultEntryConverter;
import org.bouncycastle.asn1.x509.X509NameEntryConverter;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.json.JSONObject;
import picocli.CommandLine;
import picocli.CommandLine.Help;

import javax.net.ssl.HttpsURLConnection;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.io.StringReader;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.sql.Connection;
import java.sql.Date;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Calendar;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Properties;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static java.lang.System.Logger.Level.INFO;
import static java.net.HttpURLConnection.HTTP_BAD_REQUEST;
import static java.net.HttpURLConnection.HTTP_MOVED_TEMP;
import static java.net.HttpURLConnection.HTTP_OK;

public class AuthServer {
    final static String OPEN_ID_ENDPT = "https://accounts.google.com/.well-known/openid-configuration";
    public static final String LOGIN_CALLBACK = "/login/callback";
    static System.Logger LOG = System.getLogger(AuthServer.class.getPackageName());
    static String errorHTML;
    static String successHTML;
    static String uploadHTML;

    // this will be filled in by setUpOutput and used by error() and info()
    static int screenWidth;

    static {
        try {
            errorHTML = getResource("/pages/error.html");
            successHTML = getResource("/pages/success.html");
            uploadHTML = getResource("/pages/upload.html");
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    Random rand = new Random();
    /**
     * the client_id used to talk to google services
     */
    String clientId;
    /**
     * the client_secret used to talk to google services
     */
    String clientSecret;
    /**
     * the URL that should be invoked with authentication at google finishes
     */
    String authRedirectURL;
    String httpsURLPrefix;
    /**
     * the domain (email domain) of the idea that is being authenticated
     */
    String authDomain;
    /**
     * File path to your CA private key file, read from properties file
     */
    String CAPrivateKey;
    /**
     * File path to your CA certification file, read from properties file
     */
    String CACert;
    /**
     * the endpoint used to get the JWT token
     */
    String tokenEndpoint;
    /**
     * the endpoint used to start oauth
     */
    String authEndpoint;
    /**
     * the nonces that are currently being authenticated
     */
    HashMap<String, NonceRecord> nonces = new HashMap<>();
    ScheduledExecutorService scheduledExecutor = Executors.newSingleThreadScheduledExecutor();

    public ConcurrentHashMap<String, byte[]> secureCSR = new ConcurrentHashMap<>();
    private Connection connection;

    AuthServer(Properties properties) throws IOException {
        this.clientId = getProperty(properties, "clientId");
        this.clientSecret = getProperty(properties, "clientSecret");
        this.authRedirectURL = getProperty(properties, "redirectURL");
        this.authDomain = getProperty(properties, "authDomain");
        this.CAPrivateKey = getProperty(properties, "CAPrivateKey");
        this.CACert = getProperty(properties, "CACert");
        var authDBFile = getProperty(properties, "authDBFile");


        var indexOfPath = authRedirectURL.indexOf('/', 8); // find the / just past the https://
        if (indexOfPath == -1) {
            this.httpsURLPrefix = authRedirectURL;
        } else {
            this.httpsURLPrefix = authRedirectURL.substring(0, indexOfPath);
        }

        var endptsStr = new String(new URL(OPEN_ID_ENDPT).openConnection().getInputStream().readAllBytes());
        var endpts = new JSONObject(endptsStr);
        tokenEndpoint = endpts.getString("token_endpoint");
        authEndpoint = endpts.getString("authorization_endpoint");

        try {
            this.connection = DriverManager.getConnection(authDBFile);
            checkAuthTable();
        } catch (SQLException e) {
            System.out.println("problem accessing database: " + e.getMessage());
            System.exit(3);
        }
    }

    static private String getResource(String path) throws IOException {
        try (var stream = AuthServer.class.getResourceAsStream(path)) {
            if (stream == null) throw new FileNotFoundException(path);
            return new String(stream.readAllBytes());
        }
    }

    private static void redirect(HttpExchange exchange, String redirectURL) throws IOException {
        exchange.getRequestBody().close();
        exchange.getResponseHeaders().add("Location", redirectURL);
        exchange.sendResponseHeaders(HTTP_MOVED_TEMP, 0);
        exchange.getResponseBody().write(String.format("<a href=%1$s>%1$s</a>", redirectURL).getBytes());
        exchange.getResponseBody().close();
    }

    private static HashMap<String, String> extractParams(HttpExchange exchange) {
        var params = new HashMap<String, String>();
        for (var param : exchange.getRequestURI().getQuery().split("&")) {
            var keyVal = param.split("=", 2);
            params.put(keyVal[0], URLDecoder.decode(keyVal[1], Charset.defaultCharset()));
        }
        return params;
    }

    private static void sendOKResponse(HttpExchange exchange, byte[] response) throws IOException {
        exchange.getRequestBody().close();
        exchange.sendResponseHeaders(HTTP_OK, response.length);
        try (var os = exchange.getResponseBody()) {
            os.write(response);
        }
    }

    private static void setupOutput(CommandLine cmdline) {
        var spec = cmdline.getCommandSpec();
        spec.usageMessage().autoWidth(true);
        screenWidth = spec.usageMessage().width();
    }

    public String decodeCSR(byte[] csrBytes) throws IOException, OperatorCreationException {
        String email = "";
        X509NameEntryConverter converter = new X509DefaultEntryConverter();
        PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(csrBytes)));
        var obj = pemParser.readObject();
        PKCS10CertificationRequest csr = (PKCS10CertificationRequest) obj;
        // System.out.println("ajlkdjflkad 1");
        var names = new X500Name(RFC4519Style.INSTANCE, csr.getSubject().getRDNs());
        for (var rdn : names.getRDNs()) {
            for (var tv : rdn.getTypesAndValues()) {
                if (tv.getType().equals(RFC4519Style.cn))
                    email = tv.getValue().toString();
                //System.out.println(RFC4519Style.INSTANCE.oidToDisplayName(tv.getType()) + " " + tv.getValue().toASN1Primitive());
            }
        }
        return email;
    }
    public void signCSR(byte[] csrBytes) throws IOException,
            OperatorCreationException// temporarily void until download is setup
    {
        var rand = new Random();
        var now = Calendar.getInstance();
        var expire = Calendar.getInstance();
        expire.add(Calendar.MONTH, 4);
        X509NameEntryConverter converter = new X509DefaultEntryConverter();
        PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(csrBytes)));
        var obj = pemParser.readObject();
        PKCS10CertificationRequest csr = (PKCS10CertificationRequest) obj;
        var caParser = new PEMParser(new FileReader(CAPrivateKey));
        var caPriv = (PrivateKeyInfo)caParser.readObject();
        caParser = new PEMParser(new FileReader(CACert));
        var caCert = (X509CertificateHolder)caParser.readObject();
        var names = new X500Name(RFC4519Style.INSTANCE, csr.getSubject().getRDNs());
        ASN1Primitive email = null;
        for (var rdn: names.getRDNs()) {
            for (var tv: rdn.getTypesAndValues()) {
                if (tv.getType().equals(RFC4519Style.cn)) email = tv.getValue().toASN1Primitive();
            }
        }
        var subject = new X500Name(new RDN[] {new RDN(new AttributeTypeAndValue(RFC4519Style.cn, email))});
        // from https://stackoverflow.com/questions/7230330/sign-csr-using-bouncy-castle
        var builder = new X509v3CertificateBuilder(
                caCert.getIssuer(),
                new BigInteger(128, rand),
                now.getTime(),
                expire.getTime(),
                subject,
                csr.getSubjectPublicKeyInfo()
        );
        var sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
        var digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        var signer =
                new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(PrivateKeyFactory.createKey(caPriv.getEncoded()));
        var holder = builder.build(signer);
        // replace below with file download
        var writer = new JcaPEMWriter(new FileWriter("out.pem"));
        writer.writeObject(holder);
        writer.close();
    }

    public static void main(String[] args) {
        var commandLine = new CommandLine(new Cli()).registerConverter(FileReader.class, s -> {
            try {
                return new FileReader(s);
            } catch (Exception e) {
                throw new CommandLine.TypeConversionException(e.getMessage());
            }
        });
        setupOutput(commandLine);
        int exitCode = commandLine.execute(args);
        System.exit(exitCode);
    }

    private static String getProperty(Properties properties, String key) {
        var value = properties.getProperty(key);
        if (value == null) {
            System.out.printf("%s property missing from property file\n", key);
            System.exit(1);
        }
        return value;
    }

    void checkAuthTable() throws SQLException {
        var stmt = connection.createStatement();
        stmt.execute("""
                create table if not exists authRecords (
                discordSnowflake text primary key,
                discordId text,
                email text,
                verifyDate date
                );""");
    }

    void updateAuthRecord(String discordSnowflake, String discordId, String email, Date date) throws SQLException {
        var stmt = connection.prepareStatement("""
                replace into authRecords (
                discordSnowflake,
                discordId,
                email,
                verifyDate
                ) values (?,?,?,?);""");
        stmt.setString(1, discordSnowflake);
        stmt.setString(2, discordId);
        stmt.setString(3, email);
        stmt.setDate(4, date);
        stmt.execute();
    }

    private String createAuthURL(NonceRecord nonceRecord) {
        return authEndpoint +
                "?response_type=code&scope=openid%20email" +
                "&client_id=" + URLEncoder.encode(clientId, Charset.defaultCharset()) +
                "&redirect_uri=" + URLEncoder.encode(authRedirectURL, Charset.defaultCharset()) +
                "&state=" + URLEncoder.encode(nonceRecord.state, Charset.defaultCharset()) +
                "&nonce=" + URLEncoder.encode(nonceRecord.nonce, Charset.defaultCharset()) +
                "&hd=" + URLEncoder.encode(authDomain, Charset.defaultCharset());
    }

    synchronized private void checkExpirations() {
        var toDelete = new LinkedList<String>();
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime nextExpire = null;
        for (var e : nonces.entrySet()) {
            var v = e.getValue();
            if (v.expireTime.isAfter(now)) {
                if (nextExpire == null || nextExpire.isAfter(v.expireTime)) {
                    nextExpire = v.expireTime;
                }
            } else {
                toDelete.add(e.getKey());
            }
        }
        for (var key : toDelete) {
            var nr = nonces.remove(key);
            nr.complete(null);
        }
        if (nextExpire != null) {
            scheduledExecutor.schedule(this::checkExpirations, now.until(nextExpire, ChronoUnit.SECONDS),
                    TimeUnit.SECONDS);
        }
    }

    synchronized public NonceRecord createValidation(byte[] csrFile) {
        var nonceRecord =
            new NonceRecord(Long.toHexString(rand.nextLong()), Long.toHexString(rand.nextLong()),
                    LocalDateTime.now().plus(5, ChronoUnit.MINUTES),
                    new CompletableFuture<>(), csrFile);
        if (nonces.isEmpty()) {
            scheduledExecutor.schedule(this::checkExpirations, 5, TimeUnit.MINUTES);
        }
        nonces.put(nonceRecord.nonce, nonceRecord);
        return nonceRecord;
    }

    @HttpPath(path = "/")
    public void rootPage(HttpExchange exchange) throws Exception {
        System.out.println("Reached upload page");
        sendOKResponse(exchange, uploadHTML.getBytes());
    }

    private static byte[] fullyRead(InputStream is) throws IOException {
        var baos = new ByteArrayOutputStream();
        is.transferTo(baos);
        return baos.toByteArray();
    }

    @HttpPath(path = "/upload")
    public void uploadPage(HttpExchange exchange) throws Exception {
        var fp = new MultiPartFormDataParser(exchange.getRequestBody());
        //putting into concurrent hashmap to feed into CertPOC
        var ff = fp.nextField();
        var bytes = fullyRead(ff.is);
        //nonce
        String nonce = new BigInteger(128, rand).toString();
        var nonceRecord = new NonceRecord(nonce, Long.toHexString(rand.nextLong()), LocalDateTime.now().plus(5,
                ChronoUnit.MINUTES), new CompletableFuture<>(), bytes);
        var authURL = createAuthURL(nonceRecord);
        nonces.put(nonce, nonceRecord);
        redirect(exchange, authURL);
    }

    @HttpPath(path = LOGIN_CALLBACK)
    public void loginCallback(HttpExchange exchange) throws Exception {
        HashMap<String, String> params = extractParams(exchange);
        exchange.getRequestBody().close();
        if (params.containsKey("error")) {
            redirect(exchange, String.format("/login/error?error=%s",
                    URLEncoder.encode(params.get("error"), Charset.defaultCharset())));
            return;
        }
        var code = params.get("code");
        LOG.log(INFO, "starting post");
        var con = (HttpsURLConnection) new URL(tokenEndpoint).openConnection();
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        String request =
                String.format("code=%s&client_id=%s&client_secret=%s&redirect_uri=%s&grant_type=authorization_code",
                        URLEncoder.encode(code, Charset.defaultCharset()),
                        URLEncoder.encode(clientId, Charset.defaultCharset()),
                        URLEncoder.encode(clientSecret, Charset.defaultCharset()),
                        URLEncoder.encode(authRedirectURL, Charset.defaultCharset()));
        try (OutputStream os = con.getOutputStream()) {
            os.write(request.getBytes());
        }
        var baos = new ByteArrayOutputStream();
        try (InputStream is = con.getResponseCode() < HTTP_BAD_REQUEST ? con.getInputStream() : con.getErrorStream()) {
            is.transferTo(baos);
        }
        LOG.log(INFO, "finished post");
        String response = baos.toString();
        var json = new JSONObject(response);
        if (json.has("error")) {
            redirect(exchange, String.format("/login/error?error=%s",
                    URLEncoder.encode(json.getString("error"), Charset.defaultCharset())));
            return;
        }
        // extract the email from the JWT token
        String idToken = json.getString("id_token");
        var tokenParts = idToken.split("\\.");
        var info = new JSONObject(new String(Base64.getUrlDecoder().decode(tokenParts[1])));
        var email = info.getString("email");
        var nonce = info.getString("nonce"); // use this to access csr
        var nr = nonces.get(nonce);
        if (nr == null) {
            redirect(exchange,
                    String.format("/login/error?error=%s", URLEncoder.encode("validation expired",
                            Charset.defaultCharset())));
        } else {
            String csrEmail = decodeCSR(nr.csr);
            System.out.println(csrEmail + " " + email);
            if (csrEmail.equals(email)) {
                redirect(exchange, String.format("/login/success?email=%s", URLEncoder.encode(email, Charset.defaultCharset())));
                signCSR(nr.csr);
            }
            else {
                redirect(exchange, String.format("/login/error?error=%s", URLEncoder.encode("CSR has " + csrEmail + ", but " + "authenticated with " + email), Charset.defaultCharset()));
            }
        }
    }

    @HttpPath(path = "/login/error")
    public void loginError(HttpExchange exchange) throws Exception {
        var error = extractParams(exchange).get("error");
        byte[] response = errorHTML.replace("ERROR", error).getBytes();
        sendOKResponse(exchange, response);
    }

    @HttpPath(path = "/login/success")
    public void loginSuccess(HttpExchange exchange) throws Exception {
        var email = extractParams(exchange).get("email");
        byte[] response = successHTML.replace("EMAIL", email).getBytes();
        sendOKResponse(exchange, response);
    }

    String getValidateURL(NonceRecord nr) {
        return String.format("%s/login?nonce=%s", httpsURLPrefix, nr.nonce);
    }

    record NonceRecord(String nonce, String state, LocalDateTime expireTime,
                       CompletableFuture<String> future, byte[] csr) {
        void complete(String email) {
            future.complete(email);
        }
    }

    @CommandLine.Command(name = "server", mixinStandardHelpOptions = true,
            description = "implements a simple HTTPS server for validating email addresses associated with discord " +
                    "ids using oath.")
    static class Cli implements Callable<Integer> {

        static {
            // make sure we don't miss any exceptions
            Thread.setDefaultUncaughtExceptionHandler((t, te) -> te.printStackTrace());
            System.setProperty("java.util.logging.SimpleFormatter.format", "%1$tF %1$tT %4$s %5$s%n");
        }

        static void wrapOutput(String str) {
            var line = new Help.Column(screenWidth, 0, Help.Column.Overflow.WRAP);
            var txtTable = Help.TextTable.forColumns(Help.defaultColorScheme(Help.Ansi.AUTO), line);
            txtTable.indentWrappedLines = 0;
            txtTable.addRowValues(str);
            System.out.print(txtTable);
            System.out.flush();
        }

        static void error(String message) {
            wrapOutput(Help.Ansi.AUTO.string("@|red " + message + "|@"));
        }

        static void info(String message) {
            wrapOutput(Help.Ansi.AUTO.string("@|blue " + message + "|@"));
        }

        @Override
        public Integer call() {
            CommandLine.usage(this, System.out);
            return 1;
        }

        @CommandLine.Command(name = "config", mixinStandardHelpOptions = true,
                description = "check the config file and provide guidance if needed.")
        int config(@CommandLine.Parameters(paramLabel = "prop_file",
                description = "property file containing config and creds.")
                           FileReader propFile) {
            var props = new Properties();
            try {
                props.load(propFile);
                if (props.get("clientId") == null || props.get("clientSecret") == null) {
                    error("""
                            you haven't specified the clientId and clientSecret in the config file. you can obtain them at https://console.cloud.google.com/apis/credentials.
                            create the following lines in the config file:
                            clientId=CLIENTID_FROM_GOOGLE
                            clientSecret=CLIENTSECRET_FROM_GOOGLE""");
                } else {
                    info("clientId and clientSecret look OK.");
                }
                String redirectURL = (String) props.get("redirectURL");
                if (redirectURL == null) {
                    error("missing redirectURL in the config. this will be the URL to redirect the " +
                            "browser to after google has authenticated the client.");
                } else if (!redirectURL.startsWith("http") || !redirectURL.endsWith(LOGIN_CALLBACK)) {
                    error(String.format("redirectURL must start with http and end with %s.", LOGIN_CALLBACK));
                } else {
                    info("redirectURL is set.");
                }
                if (props.get("authDomain") == null) {
                    error("missing authDomain in the config. this should specify a domain name of the id, like sjsu" +
                            ".edu .");
                } else {
                    info("authDomain is set.");
                }
                if (props.get("authDBFile") == null) {
                    error("missing the authDBFile string. this is the location of a sqlite DB.");
                } else {
                    info("authDBFIle is set.");
                }
            } catch (IOException e) {
                System.out.printf("couldn't read config file: %s\n", e.getMessage());
                return 2;
            }
            return 0;
        }

        @CommandLine.Command(name = "serve", mixinStandardHelpOptions = true,
                description = "start https verify endpoint.")
        int serve(@CommandLine.Parameters(paramLabel = "prop_file",
                description = "property file containing config and creds.")
                          FileReader propFile,
                  @CommandLine.Option(names = "--port", defaultValue = "443",
                          description = "TCP port to listen for web connections.",
                          showDefaultValue = Help.Visibility.ALWAYS)
                          int port,
                  @CommandLine.Option(names = "--noTLS",
                          description = "turn off TLS for web connections.",
                          showDefaultValue = Help.Visibility.ALWAYS)
                          boolean noTLS
        ) {
            try {
                var props = new Properties();
                props.load(propFile);

                var authServer = new AuthServer(props);

                var simpleHttpsServer = new SimpleHttpsServer(port, !noTLS);
                var added = simpleHttpsServer.addToHttpsServer(authServer);
                for (var add : added) {
                    LOG.log(INFO, "added {0}", add);
                }

                simpleHttpsServer.start();
                while (true) {
                    Thread.sleep(1000000);
                }
            } catch (IOException | NoSuchAlgorithmException | InterruptedException e) {
                e.printStackTrace();
            }
            return 0;
        }
    }
}
