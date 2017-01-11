package io.pivotal.springcloud.ssl;

import java.net.MalformedURLException;
import java.net.URL;

import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * 
 * Trusts certificates specified by environment variables CF_TARGET and TRUST_CERTS. 
 * Trust is established during application context initialization.
 * 
 * @author wtran@pivotal.io
 *
 */
public class CloudFoundryCertificateTruster implements ApplicationContextInitializer<ConfigurableApplicationContext> {

	private static final CloudFoundryCertificateTruster instance = new CloudFoundryCertificateTruster();
	private EnvironmentVariableResolver env = new EnvironmentVariableResolver();
	private SslCertificateTruster sslCertificateTruster = SslCertificateTruster.instance;
	/**
	 * If the CF_TARGET env var starts with https://, gets the certificate for
	 * that host and trust it if untrusted. If no CF_TARGET env var is present,
	 * or if the certificate is already trusted, no changes are made.
	 * 
	 * Also supports trusting certificates listed in the env var TRUST_CERTS, a
	 * comma separated list of hostname:port.
	 */

	public static void trustCertificates() {
		instance.trustCertificatesInternal();
	}

	void trustCertificatesInternal() {
		String cfTarget = env.getValue("CF_TARGET");
		if (cfTarget != null) {
			try {
				URL cfTargetUrl = new URL(cfTarget);
				String host = cfTargetUrl.getHost();
				if ("https".equals(cfTargetUrl.getProtocol()) && host != null) {
					int httpsPort = cfTargetUrl.getPort() > 0 ? cfTargetUrl.getPort() : 443;
					try {
						sslCertificateTruster.trustCertificateInternal(host, httpsPort, 5000);
						System.out.println("trusting certificate at " + host + ":" + httpsPort + " succeeded.");
					} catch (Exception e) {
						System.err.println("trusting certificate at " + host + ":" + httpsPort + " failed due to " + e);
						e.printStackTrace();
					}
				}
			} catch (MalformedURLException e1) {
				System.err.println("Cannot parse CF_TARGET '"+cfTarget+"' as a URL");
			}
		}
		String trustCerts = env.getValue("TRUST_CERTS");
		if (trustCerts != null) {
			for (String hostAndPort : trustCerts.split(",")) {
				String[] parts = hostAndPort.split(":");
				String host = parts[0];
				int port = 443;
				try {
					port = Integer.parseInt(parts[1]);
				} catch (Exception e) {
				}
				if (host != null && host.length() > 0 && port > 0 && port < 65536) {
					try {
						sslCertificateTruster.trustCertificateInternal(host, port, 5000);
					} catch (Exception e) {
						System.err.println("trusting certificate at " + host + ":" + port + " failed due to " + e);
						e.printStackTrace();
					}
				}
			}
		}
	}

	static {
		trustCertificates();
	}

	@Override
	public void initialize(ConfigurableApplicationContext applicationContext) {
	}
	
	static class EnvironmentVariableResolver {
		String getValue(String key) {
			return System.getenv(key);
		}
	}

}