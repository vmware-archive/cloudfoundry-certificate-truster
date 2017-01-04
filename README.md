# cloudfoundry-certificate-truster

When added to your Spring Boot project's dependencies, the CloudFoundryCertificateTruster will download certificates and add them to the JVM truststore at the earliest possible time. Certificates can be specified by either or both of the following environment variables:

```
CF_TARGET=https://api.my-cf-domain.com
``` 

This will cause the CloudFoundryCertificateTruster to download the certificate at api.my-cf-domain.com:443 and add it to the JVM's truststore

```
TRUST_CERTS=api.foo.com,api.bar.com:8443
``` 
This will cause the CloudFoundryCertificateTruster to download the certificates at api.foo.com:443 and api.bar.com:8443 and add them to the JVM's truststore. You can specify one or more comma separated hostnames, optionally with a port.

The timeout for certificate download is 5 seconds. If any errors occur, they are printed to System.err.

## Maven Dependency

```xml
<!-- Pivotal cloudfoundry-certificate-truster -->
<dependency>
    <groupId>io.pivotal.spring.cloud</groupId>
    <artifactId>cloudfoundry-certificate-truster</artifactId>
    <version>1.0.1.RELEASE</version>
</dependency>
```
