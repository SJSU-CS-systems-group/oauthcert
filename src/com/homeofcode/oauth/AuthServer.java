package com.homeofcode.oauth;

import com.homeofcode.https.HttpPath;
import com.homeofcode.https.SimpleHttpsServer;
import com.sun.net.httpserver.HttpExchange;
import org.json.JSONObject;
import picocli.CommandLine;
import picocli.CommandLine.Help;

import javax.net.ssl.HttpsURLConnection;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.Date;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Properties;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
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

    private Connection connection;

    AuthServer(Properties properties) throws IOException {
        this.clientId = getProperty(properties, "clientId");
        this.clientSecret = getProperty(properties, "clientSecret");
        this.authRedirectURL = getProperty(properties, "redirectURL");
        this.authDomain = getProperty(properties, "authDomain");
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

    synchronized public NonceRecord createValidation() {
        var nonceRecord =
                new NonceRecord(Long.toHexString(rand.nextLong()), Long.toHexString(rand.nextLong()),
                        LocalDateTime.now().plus(5, ChronoUnit.MINUTES),
                        new CompletableFuture<>());
        if (nonces.isEmpty()) {
            scheduledExecutor.schedule(this::checkExpirations, 5, TimeUnit.MINUTES);
        }
        nonces.put(nonceRecord.nonce, nonceRecord);
        return nonceRecord;
    }

    @HttpPath(path = "/test")
    public void testPage(HttpExchange exchange) throws Exception {
        var nr = createValidation();
        redirect(exchange, getValidateURL(nr));
    }

    @HttpPath(path = "/")
    public void rootPage(HttpExchange exchange) throws Exception {
        System.out.println("Reached upload page");
        sendOKResponse(exchange, uploadHTML.getBytes());
    }

    @HttpPath(path = "/upload")
    public void uploadPage(HttpExchange exchange) throws Exception{
        var dataCSR = exchange.getRequestBody();

        int C;

        while ((C = exchange.getRequestBody().read()) != -1){
            System.out.write(C);
        }

        //look up HttpExchange file upload
    }

    @HttpPath(path = "/login")
    synchronized public void loginPage(HttpExchange exchange) throws Exception {
        var nonce = extractParams(exchange).get("nonce");
        var nonceRecord = nonces.get(nonce);
        var authURL = createAuthURL(nonceRecord);
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
        var nonce = info.getString("nonce");
        var nr = nonces.get(nonce);
        if (nr == null) {
            redirect(exchange,
                    String.format("/login/error?error=%s", URLEncoder.encode("validation expired",
                            Charset.defaultCharset())));
        } else {
            nr.complete(email);
            redirect(exchange,
                    String.format("/login/success?email=%s", URLEncoder.encode(email, Charset.defaultCharset())));
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
                       CompletableFuture<String> future) {
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
            var txtTable = Help.TextTable.forColumns(Help.defaultColorScheme(Help.Ansi.AUTO), new Help.Column[] {line});
            txtTable.indentWrappedLines = 0;
            txtTable.addRowValues(str);
            System.out.print(txtTable.toString());
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
                String redirectURL = (String)props.get("redirectURL");
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
                  @CommandLine.Option(names = "--port", required = false, defaultValue = "443",
                          description = "TCP port to listen for web connections.",
                          showDefaultValue = Help.Visibility.ALWAYS)
                  int port,
                  @CommandLine.Option(names = "--noTLS", required = false,
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