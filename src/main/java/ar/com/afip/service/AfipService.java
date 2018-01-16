package ar.com.afip.service;

import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

public class AfipService {

    public String generateLoginCMS() throws Exception {
        String tra1 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<loginTicketRequest version=\"1.0\">\n" +
                " <header>\n" +
                "  <source>SERIALNUMBER=CUIT 2032996607, CN=pablocert</source>\n" +
                "  <destination>cn=wsaahomo,o=afip,c=ar,serialNumber=CUIT 33693450239</destination>\n" +
                "  <uniqueId>4325399</uniqueId>\n" +
                "  <generationTime>2017-03-20T18:00:00-03:00</generationTime>\n" +
                "  <expirationTime>2017-03-20T20:10:00-03:00</expirationTime>\n" +
                " </header>\n" +
                " <service>wsfe</service>\n" +
                "</loginTicketRequest>";

        String tra = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<loginTicketRequest version=\"1.0\">\n" +
                " <header>\n" +
                "  <uniqueId>1279058341</uniqueId>\n" +
                "  <generationTime>2018-01-16T13:19:01</generationTime>\n" +
                "  <expirationTime>2018-01-16T14:39:01</expirationTime>\n" +
                " </header>\n" +
                " <service>wsfe</service>\n" +
                "</loginTicketRequest>";

        String p12pass = "pablito1";
        String signer = "pablito";
        File p12file = new File("pfelitti.p12");

        //openssl req -new -key privada.key -subj "C=ar, O=empresa1, SERIALNUMBER=CUIT 20329966071, CN=sistfacturacion" -out pedido.csr
        //openssl pkcs12 -export -inkey privada.key -in certificado.crt -out pfelitti.p12 -name "pablito"

        // Create a new empty CMS Message
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

        // Add a Signer to the Message
        KeyStore ks = KeyStore.getInstance("pkcs12");
        FileInputStream p12stream = new FileInputStream(p12file);
        ks.load(p12stream, p12pass.toCharArray());
        p12stream.close();
        PrivateKey pKey = (PrivateKey) ks.getKey(signer, p12pass.toCharArray());
        X509Certificate pCertificate = (X509Certificate) ks.getCertificate(signer);
        gen.addSigner(pKey, pCertificate, CMSSignedDataGenerator.DIGEST_SHA1);

        // Add the Certificate to the Message
        ArrayList<X509Certificate> certList = new ArrayList<X509Certificate>();
        certList.add(pCertificate);

        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        CertStore cstore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC");
        gen.addCertificatesAndCRLs(cstore);

        // Add the data (XML) to the Message
        CMSProcessable data = new CMSProcessableByteArray(tra.getBytes());

        // Add a Sign of the Data to the Message
        CMSSignedData signed = gen.generate(data, true, "BC");

        //
        byte[] asn1_cms = signed.getEncoded();

        return DatatypeConverter.printBase64Binary(asn1_cms);
    }
}
