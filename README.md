# cloudfoundry-certificate-truster

When added to your Spring Boot project's dependencies, the CloudFoundryCertificateTruster will download certificates
and add them to the JVM truststore at the earliest possible time. Certificates can be specified by the following environment variable:

```
CF_TARGET=https://api.my-cf-domain.com
```

This will cause the CloudFoundryCertificateTruster to download the certificate at api.my-cf-domain.com:443 and add
it to the JVM's truststore

The timeout for certificate download is 5 seconds. If any errors occur, they are printed to System.err.

## Development

1. Clone the repo
2. Run the tests - `./gradlew build`
3. Make your changes
4. Make sure the tests are green
5. Push code to GitHub.

## CI

Built on [Bamboo](https://build.spring.io/browse/CLOUD-CFCT).

You need to be added to a permissions group to see this in the Bamboo dashboard.
