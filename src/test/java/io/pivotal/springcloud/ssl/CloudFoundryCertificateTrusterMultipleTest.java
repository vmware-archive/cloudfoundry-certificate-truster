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

public class CloudFoundryCertificateTrusterMultipleTest {

	private CloudFoundryCertificateTruster cfCertTruster;

	@Mock
	private EnvironmentVariableResolver env;
	
	@Mock
	private SslCertificateTruster sslCertTruster;

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

	@Test
	public void testMultipleTargets() throws Exception {
		
		final String cfTargets = "https://api.foo.com,https://api.foo.com:8080";
		final String[] expectedHosts = new String[] { "api.foo.com", "api.foo.com" };
		final int[] expectedPorts = new int[] { 443, 8080 };
		
		final int count = cfTargets.split(",").length;
		
		Mockito.when(env.getValue("CF_TARGET")).thenReturn(cfTargets);

		cfCertTruster.trustCertificatesInternal();

		ArgumentCaptor<String> hostCaptor = ArgumentCaptor.forClass(String.class);
		ArgumentCaptor<Integer> portCaptor = ArgumentCaptor.forClass(int.class);
		ArgumentCaptor<Integer> timeoutCaptor = ArgumentCaptor.forClass(int.class);
		Mockito.verify(sslCertTruster, Mockito.times(count)).trustCertificateInternal(
				hostCaptor.capture(),
				portCaptor.capture(),
				timeoutCaptor.capture());
		
		List<String> hosts = hostCaptor.getAllValues();
		List<Integer> ports = portCaptor.getAllValues();
		List<Integer> timeouts = timeoutCaptor.getAllValues();
		
		for (int i = 0; i < count; i++) {
			Assert.assertEquals(expectedHosts[i], hosts.get(i));
			Assert.assertEquals(expectedPorts[i], ports.get(i).intValue());
			Assert.assertEquals(new Integer(5000), timeouts.get(i));
		}

	}


}
