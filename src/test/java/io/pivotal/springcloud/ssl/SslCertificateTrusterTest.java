package io.pivotal.springcloud.ssl;

import java.security.KeyStore;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.junit.Assert;
import org.junit.Test;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

public class SslCertificateTrusterTest {

	@Test
	public void testTimeout() throws Exception {
		Thread runner = new Thread() {
			@Override
			public void run() {
				try {
					SslCertificateTruster.trustCertificate("foo.nonexistant", 443, 1000);
				} catch (Exception e) {
				}
			}
		};
		runner.start();
		runner.join(5000);
		Assert.assertFalse(runner.isAlive());
		runner.interrupt();
	}

	@Test
	public void appendToTruststore() throws Exception {
		// generate self-signed cert
		CertAndKeyGen keyGen = new CertAndKeyGen("RSA", "SHA1WithRSA", null);
		keyGen.generate(1024);
		X509Certificate selfsigned = keyGen.getSelfCertificate(new X500Name("CN=foo.nonexistant"), (long) 365 * 24 * 3600);

		SslCertificateTruster.appendToTruststore(new X509Certificate[] { selfsigned });

		// verify defaultTrustManager contains cert
		TrustManagerFactory trustManagerFactory =
				TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		// this will initialize with the first valid keystore
		// 1. javax.net.ssl.trustStore
		// 2. jssecerts
		// 3. cacerts
		// see https://github.com/openjdk-mirror/jdk7u-jdk/blob/master/src/share/classes/sun/security/ssl/TrustManagerFactoryImpl.java#L130
		trustManagerFactory.init((KeyStore) null);
		X509TrustManager defaultTrustManager = (X509TrustManager) trustManagerFactory.getTrustManagers()[0];
		X509Certificate[] cacerts = defaultTrustManager.getAcceptedIssuers();
		for (X509Certificate certificate : cacerts) {
			if (certificate.equals(selfsigned)) {
				return;
			}
		}
		Assert.fail();
	}
}
