package com.homeofcode.oauthcert;

import org.bouncycastle.asn1.ASN1Primitive;
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
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Calendar;
import java.util.Random;

public class CertPOC {
    public static void main(String[] args) throws IOException, OperatorCreationException {
        var rand = new Random();
        var now = Calendar.getInstance();
        var expire = Calendar.getInstance();
        expire.add(Calendar.MONTH, 4);
        X509NameEntryConverter converter = new X509DefaultEntryConverter();
        var csr = readFromFile(args[0], PKCS10CertificationRequest.class);
        var ca = readFromFile(args[1], X509CertificateHolder.class);
        var caPriv = readFromFile(args[2], PrivateKeyInfo.class);
        var names = new X500Name(RFC4519Style.INSTANCE, csr.getSubject().getRDNs());
        ASN1Primitive email = null;
        for (var rdn: names.getRDNs()) {
            for (var tv: rdn.getTypesAndValues()) {
                if (tv.getType().equals(RFC4519Style.cn)) email = tv.getValue().toASN1Primitive();
                System.out.println(RFC4519Style.INSTANCE.oidToDisplayName(tv.getType()) + " " + tv.getValue().toASN1Primitive());
            }
        }
        System.out.println("email = " + email);
        var subject = new X500Name(new RDN[] {new RDN(new AttributeTypeAndValue(RFC4519Style.cn, email))});

        // from https://stackoverflow.com/questions/7230330/sign-csr-using-bouncy-castle

        var builder = new X509v3CertificateBuilder(
                ca.getIssuer(),
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

        var writer = new JcaPEMWriter(new FileWriter("out.pem"));
        writer.writeObject(holder);
        writer.close();
    }

    private static <T> T readFromFile(String filepath, Class<T> clazz) throws IOException {
        var parser = new PEMParser(new FileReader(filepath));
        var obj = parser.readObject();
        if (!(obj.getClass() == clazz)) {
            System.out.println("expected " + clazz.getName() +" got " + obj.getClass().getName());
            System.exit(2);
        }
        return (T)obj;
    }
}