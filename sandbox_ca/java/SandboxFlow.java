/*
 * Headless end-to-end check for a CertWizard build patched by
 * sandbox_ca.java_kit.  It uses only public CertWizard classes, so it also
 * serves as a worked example of the protocol calls the GUI makes.
 *
 * Compile and run against the patched jar:
 *
 *   javac -cp CertWizard-sandbox.jar -d /tmp sandbox_ca/java/SandboxFlow.java
 *   java -cp /tmp:CertWizard-sandbox.jar SandboxFlow
 *
 * The sandbox should be in auto-sign mode (the default) so the status lookup
 * after each submission issues the certificate.
 */
import uk.ngs.ca.certificate.CertificateRequestCreator;
import uk.ngs.ca.certificate.OnlineCertRenewRequest;
import uk.ngs.ca.certificate.OnlineHostCertRequest;
import uk.ngs.ca.certificate.OnlineUserCertRequest;
import uk.ngs.ca.certificate.chain.CertChainBuilder;
import uk.ngs.ca.certificate.client.CertificateDownload;
import uk.ngs.ca.certificate.client.ResourcesPublicKey;
import uk.ngs.ca.certificate.client.RevokeRequest;
import uk.ngs.ca.common.Pair;
import uk.ngs.ca.common.SystemStatus;
import uk.ngs.ca.tools.property.SysProperty;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

public final class SandboxFlow {

    private static final String PIN = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";
    private static final String EMAIL = "java.sandbox@example.org";

    private SandboxFlow() {
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static String certificateId(ResourcesPublicKey lookup) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        String id = (String) xpath.compile("//certificate/id")
                .evaluate(lookup.getDocument(), XPathConstants.STRING);
        if (id == null || id.isEmpty()) {
            throw new IllegalStateException("no certificate id in the lookup response");
        }
        return id;
    }

    private static void trustThePatchedBuild() throws Exception {
        SystemStatus.getInstance().setCwDataDirectory(Files.createTempDirectory("cw-sandbox-flow").toFile());
        SysProperty.setupTrustStore();
        String directory = SystemStatus.getInstance().getCwDataDirectory().getAbsolutePath();
        System.setProperty("javax.net.ssl.trustStore",
                directory + java.io.File.separator + SysProperty.getValue("ngsca.truststore.file"));
        System.setProperty("javax.net.ssl.trustStorePassword",
                SysProperty.getValue("ngsca.cert.truststore.password"));
    }

    public static void main(String[] args) throws Exception {
        trustThePatchedBuild();

        KeyPair userKeys = rsa();
        String userDn = "CN=java sandbox user,OU=Test,O=Sandbox,C=UK";
        String userCsr = new CertificateRequestCreator(userDn, EMAIL)
                .createCertificateRequest(userKeys.getPrivate(), userKeys.getPublic());
        OnlineUserCertRequest userRequest = new OnlineUserCertRequest(userCsr, PIN, EMAIL);
        System.out.println("user-submit=" + userRequest.isCSRREquestSuccess());
        if (!userRequest.isCSRREquestSuccess()) {
            throw new IllegalStateException(userRequest.getMessage());
        }

        ResourcesPublicKey userLookup = new ResourcesPublicKey(userKeys.getPublic());
        if (userLookup.isExist()) {
            throw new IllegalStateException("the sandbox does not know the user key");
        }
        String userId = certificateId(userLookup);
        X509Certificate userCert = new CertificateDownload(userId).getCertificate();
        if (userCert == null) {
            throw new IllegalStateException("user certificate download failed");
        }
        System.out.println("user-cert=" + userId + " " + userCert.getSubjectX500Principal().getName());
        String issuer = userCert.getIssuerX500Principal().getName();
        boolean issuerConfigured = java.util.Arrays.asList(
                SysProperty.getValue("ngsca.issuer.dn").split(";")).contains(issuer);
        System.out.println("user-issuer=" + issuer + " configured=" + issuerConfigured);
        if (!issuerConfigured) {
            throw new IllegalStateException("ngsca.issuer.dn in the patched client does not name " + issuer);
        }
        CertChainBuilder.Result chain = CertChainBuilder.offline().build(userCert, java.util.Collections.<java.security.cert.Certificate>emptyList());
        System.out.println("user-chain=" + chain.getChain().size() + " complete=" + chain.isComplete());
        if (!chain.isComplete()) {
            throw new IllegalStateException("sandbox chain did not reach a trusted root: " + chain.getProblems());
        }

        KeyPair hostKeys = rsa();
        String hostDn = "CN=host.sandbox.test,OU=Test,O=Sandbox,C=UK";
        String hostCsr = new CertificateRequestCreator(hostDn, EMAIL)
                .createCertificateRequest(hostKeys.getPrivate(), hostKeys.getPublic());
        Pair<Boolean, String> host = new OnlineHostCertRequest(
                userCert, userKeys.getPrivate(), hostCsr, PIN, EMAIL).doHostCSR();
        System.out.println("host-submit=" + host.first + " " + host.second);
        if (!Boolean.TRUE.equals(host.first)) {
            throw new IllegalStateException(host.second);
        }
        if (new ResourcesPublicKey(hostKeys.getPublic()).isExist()) {
            throw new IllegalStateException("the sandbox does not know the host key");
        }

        KeyPair renewKeys = rsa();
        OnlineCertRenewRequest renewal = new OnlineCertRenewRequest(
                userCert, userKeys.getPrivate(), renewKeys, EMAIL);
        Pair<Boolean, String> renewed = renewal.doRenewal();
        System.out.println("renew-submit=" + renewed.first + " " + renewed.second);
        if (!Boolean.TRUE.equals(renewed.first)) {
            throw new IllegalStateException(renewed.second);
        }
        if (new ResourcesPublicKey(renewKeys.getPublic()).isExist()) {
            throw new IllegalStateException("the sandbox does not know the renewed key");
        }

        RevokeRequest revoke = new RevokeRequest(
                userKeys.getPrivate(), Long.parseLong(userId), "Key compromise");
        if (!revoke.doPosts()) {
            throw new IllegalStateException(revoke.getMessage());
        }
        System.out.println("revoke=ok");
        System.out.println("SANDBOX-FLOW-OK");
    }
}
