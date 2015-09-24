package io.pivotal.springcloud.ssl;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.util.ReflectionUtils;

import io.pivotal.springcloud.ssl.CloudFoundryCertificateTruster.EnvironmentVariableResolver;

@RunWith(Parameterized.class)
public class CloudFoundryCertificateTrusterTest {

	private CloudFoundryCertificateTruster cfCertTruster;

	@Mock
	private EnvironmentVariableResolver env;
	@Mock
	private SslCertificateTruster sslCertTruster;

	private String cfTarget;

	private String trustCerts;

	private List<String> expectedHosts;

	private List<Integer> expectedPorts;

	public CloudFoundryCertificateTrusterTest(String cfTarget, String trustCerts, List<String> expectedHosts,
			List<Integer> expectedPorts) {
		super();
		this.cfTarget = cfTarget;
		this.trustCerts = trustCerts;
		this.expectedHosts = expectedHosts;
		this.expectedPorts = expectedPorts;
	}

	@Before
	public void setup() throws IllegalArgumentException, IllegalAccessException {
		MockitoAnnotations.initMocks(this);
		cfCertTruster = new CloudFoundryCertificateTruster();
		Field envField = ReflectionUtils.findField(CloudFoundryCertificateTruster.class, "env");
		ReflectionUtils.makeAccessible(envField);
		ReflectionUtils.setField(envField, cfCertTruster, env);
		Field sslCertTrusterInstanceField = ReflectionUtils.findField(SslCertificateTruster.class, "instance");
		ReflectionUtils.makeAccessible(sslCertTrusterInstanceField);
		Field modifiersField = ReflectionUtils.findField(Field.class, "modifiers");
		modifiersField.setAccessible(true);
		modifiersField
				.setInt(sslCertTrusterInstanceField, sslCertTrusterInstanceField.getModifiers() & ~Modifier.FINAL);
		ReflectionUtils.setField(sslCertTrusterInstanceField, SslCertificateTruster.class, sslCertTruster);
	}

	@Parameters
	public static List<Object[]> parameters() {
		return Arrays.asList(new Object[][] {
				{ null, null, null, null },
				{ "http://api.foo.com", null, null, null },
				{ "http://api.foo.com:8080", null, null, null },
				{ "http://api.foo.com:8080/v2", null, null, null },
				{ "https://api.foo.com", null,
						Arrays.asList("api.foo.com"),
						Arrays.asList(443) },
				{ "https://api.foo.com/v2", null,
						Arrays.asList("api.foo.com"),
						Arrays.asList(443) },
				{ "https://api.foo.com:8443", null,
						Arrays.asList("api.foo.com"),
						Arrays.asList(8443) },
				{ "https://api.foo.com:8443/v2", null,
						Arrays.asList("api.foo.com"),
						Arrays.asList(8443) },
				{ null, "api.foo.com",
						Arrays.asList("api.foo.com"),
						Arrays.asList(443) },
				{ null, "api.foo.com:8443",
						Arrays.asList("api.foo.com"),
						Arrays.asList(8443) },
				{ null, "api.foo.com,api.bar.com",
						Arrays.asList("api.foo.com", "api.bar.com"),
						Arrays.asList(443, 443) },
				{ null, "api.foo.com:8443,api.bar.com:9443",
						Arrays.asList("api.foo.com", "api.bar.com"),
						Arrays.asList(8443, 9443) },
				{ "https://api.baz.com:7443/v2", "api.foo.com:8443,api.bar.com:9443",
						Arrays.asList("api.baz.com", "api.foo.com", "api.bar.com"),
						Arrays.asList(7443, 8443, 9443) },
		});
	}

	@Test
	public void testCfCertTruster()
			throws Exception {
		Mockito.when(env.getValue("CF_TARGET")).thenReturn(cfTarget);
		Mockito.when(env.getValue("TRUST_CERTS")).thenReturn(trustCerts);

		cfCertTruster.trustCertificatesInternal();

		if (expectedHosts == null) {
			Mockito.verifyZeroInteractions(sslCertTruster);
		} else {
			ArgumentCaptor<String> hostCaptor = ArgumentCaptor.forClass(String.class);
			ArgumentCaptor<Integer> portCaptor = ArgumentCaptor.forClass(int.class);
			Mockito.verify(sslCertTruster, Mockito.times(expectedHosts.size())).trustCertificateInternal(
					hostCaptor.capture(),
					portCaptor.capture(),
					Mockito.anyInt());
			Assert.assertEquals(expectedHosts, hostCaptor.getAllValues());
			Assert.assertEquals(expectedPorts, portCaptor.getAllValues());
		}

	}


}