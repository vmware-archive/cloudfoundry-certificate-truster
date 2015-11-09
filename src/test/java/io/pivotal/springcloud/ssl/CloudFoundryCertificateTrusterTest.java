package io.pivotal.springcloud.ssl;

import io.pivotal.springcloud.ssl.CloudFoundryCertificateTruster.EnvironmentVariableResolver;

import java.lang.reflect.Field;
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

@RunWith(Parameterized.class)
public class CloudFoundryCertificateTrusterTest {

	private CloudFoundryCertificateTruster cfCertTruster;

	@Mock
	private EnvironmentVariableResolver env;
	@Mock
	private SslCertificateTruster sslCertTruster;

	private String cfTarget;

	private String expectedHost;

	private Integer expectedPort;

	public CloudFoundryCertificateTrusterTest(String cfTarget, String expectedHost,
											  Integer expectedPort) {
		super();
		this.cfTarget = cfTarget;
		this.expectedHost = expectedHost;
		this.expectedPort = expectedPort;
	}

	@Before
	public void setup() throws IllegalArgumentException, IllegalAccessException {
		MockitoAnnotations.initMocks(this);
		cfCertTruster = new CloudFoundryCertificateTruster();
		Field envField = ReflectionUtils.findField(CloudFoundryCertificateTruster.class, "env");
		ReflectionUtils.makeAccessible(envField);
		ReflectionUtils.setField(envField, cfCertTruster, env);
		Field sslCertTrusterField = ReflectionUtils.findField(CloudFoundryCertificateTruster.class,
				"sslCertificateTruster");
		ReflectionUtils.makeAccessible(sslCertTrusterField);
		ReflectionUtils.setField(sslCertTrusterField, cfCertTruster, sslCertTruster);
	}

	@Parameters
	public static List<Object[]> parameters() {
		return Arrays.asList(new Object[][] {
				{ null, null, null },
				{ "http://api.foo.com", null, null },
				{ "http://api.foo.com:8080", null, null },
				{ "http://api.foo.com:8080/v2", null, null },
				{ "https://api.foo.com", "api.foo.com", 443},
				{ "https://api.foo.com/v2", "api.foo.com", 443 },
				{ "https://api.foo.com:8443", "api.foo.com", 8443},
				{ "https://api.foo.com:8443/v2", "api.foo.com", 8443},
		});
	}

	@Test
	public void testCfCertTruster()
			throws Exception {
		Mockito.when(env.getValue("CF_TARGET")).thenReturn(cfTarget);

		cfCertTruster.trustCertificatesInternal();

		if (expectedHost == null) {
			Mockito.verifyZeroInteractions(sslCertTruster);
		} else {
			ArgumentCaptor<String> hostCaptor = ArgumentCaptor.forClass(String.class);
			ArgumentCaptor<Integer> portCaptor = ArgumentCaptor.forClass(int.class);
			ArgumentCaptor<Integer> timeoutCaptor = ArgumentCaptor.forClass(int.class);
			Mockito.verify(sslCertTruster, Mockito.times(1)).trustCertificateInternal(
					hostCaptor.capture(),
					portCaptor.capture(),
					timeoutCaptor.capture());
			Assert.assertEquals(expectedHost, hostCaptor.getValue());
			Assert.assertEquals(expectedPort, portCaptor.getValue());
			Assert.assertEquals(new Integer(5000), timeoutCaptor.getValue());
		}

	}


}
