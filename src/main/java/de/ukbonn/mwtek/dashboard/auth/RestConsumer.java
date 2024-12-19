/*
 * Copyright (C) 2021 University Hospital Bonn - All Rights Reserved You may use, distribute and
 * modify this code under the GPL 3 license. THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT
 * PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR
 * OTHER PARTIES PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR
 * IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH
 * YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR
 * OR CORRECTION. IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING WILL ANY
 * COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS THE PROGRAM AS PERMITTED ABOVE,
 * BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF DATA
 * OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF THE
 * PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGES. You should have received a copy of the GPL 3 license with *
 * this file. If not, visit http://www.gnu.de/documents/gpl-3.0.en.html
 */

package de.ukbonn.mwtek.dashboard.auth;

import de.ukbonn.mwtek.dashboard.configuration.AbstractRestConfiguration;
import java.io.*;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.SSLContext;
import java.net.HttpURLConnection;
import java.net.URL;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.util.ResourceUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.HttpHeaders;
import org.json.*;
import java.util.Collections;

/** Base class for all rest consumer in this project. */
@Slf4j
public class RestConsumer {

  protected AbstractRestConfiguration restConfiguration;

  public RestConsumer(AbstractRestConfiguration restConfiguration) {
    this.restConfiguration = restConfiguration;
  }

  public boolean isUsed() {
    return restConfiguration.isUse();
  }

  /**
   * Provides a {@link RestTemplate} depending on the chosen method.
   *
   * @return {@link RestTemplate} initialized with the settings from the runtime configuration
   */
  public synchronized RestTemplate getRestTemplate() {
    String method = restConfiguration.getAuthMethod();

    if ((method == null) || (method.isEmpty())) {
      // default
      return getRestTemplateBasicAuth();
    } // if

    switch (method.toUpperCase()) {
      case "BASIC" -> {
        return getRestTemplateBasicAuth();
      } // case
      case "SSL" -> {
        return getRestTemplateCertificateAuth();
      } // case
      case "NONE" -> {
        return getRestTemplateNone();
      } // case
      case "TOKEN" -> {
        return getRestTemplateToken();
      } // case
      default -> {
        return getRestTemplateBasicAuth();
      } // default
    } // switch
  }

  /**
   * helper for REST calls without Auth
   *
   * @return a pre configured spring RestTemplate object
   */
  protected RestTemplate getRestTemplateNone() {
    RestTemplate result = new RestTemplateBuilder().build();
    result.getMessageConverters().add(0, new StringHttpMessageConverter(StandardCharsets.UTF_8));
    return result;
  }

  /**
   * helper for REST calls that use keycloak token authentication
   *
   * @return a pre configured spring RestTemplate object
   */
  protected RestTemplate getRestTemplateToken() {
    String accessToken = "";

    try {
      String tokenUrl = restConfiguration.getTokenUrl();
      String clientId = restConfiguration.getClientId();
      String clientSecret = restConfiguration.getClientSecret();

      // create post request to fetch access token
      String body = "client_id=" + clientId + "&client_secret=" + clientSecret + "&grant_type=client_credentials";
      URL url = new URL(tokenUrl);
      HttpURLConnection connection = (HttpURLConnection) url.openConnection();
      connection.setRequestMethod("POST");
      connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
      connection.setDoOutput(true);

      // write the post body
      try (OutputStream os = connection.getOutputStream()) {
        byte[] input = body.getBytes(StandardCharsets.UTF_8);
        os.write(input, 0, input.length);
      }

      // get response
      try (BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
          response.append(line);
        }

        // extract access token from response
        accessToken = new JSONObject(response.toString()).getString("access_token");

      } catch (IOException e) {
        log.error("Couldn't fetch access token due to: " + connection.getResponseMessage() +
                " (Code: " + connection.getResponseCode() + ")");
      }
    } catch (Exception e) {
      log.error("Couldn't fetch access token due to following exception: " + e.getMessage());
    }

    // build rest template
    RestTemplate result = new RestTemplateBuilder().build();
    result.getMessageConverters().add(0, new StringHttpMessageConverter(StandardCharsets.UTF_8));

    // use interceptor to add fetched access token to request
    String finalAccessToken = accessToken;
    ClientHttpRequestInterceptor bearerTokenInterceptor = (request, body, execution) -> {
      request.getHeaders().set(HttpHeaders.AUTHORIZATION, "Bearer " + finalAccessToken);
      return execution.execute(request, body);
    };

    result.setInterceptors(Collections.singletonList(bearerTokenInterceptor));

    return result;
  }

  /**
   * helper for REST calls that use Basic Authentication
   *
   * @return a pre configured spring RestTemplate object
   */
  protected RestTemplate getRestTemplateBasicAuth() {
    RestTemplate result =
        new RestTemplateBuilder()
            .basicAuthentication(
                restConfiguration.getRestUser(), restConfiguration.getRestPassword())
            .build();
    result.getMessageConverters().add(0, new StringHttpMessageConverter(StandardCharsets.UTF_8));
    return result;
  }

  /**
   * Helper for rest calls that use x509 cert authentication
   *
   * @return {@link RestTemplate} initialized with the settings from the runtime configuration
   */
  protected RestTemplate getRestTemplateCertificateAuth() {
    String keystore = restConfiguration.getKeyStore();
    String truststore = restConfiguration.getTrustStore();
    char[] truststorePassword = restConfiguration.getTrustStorePassword().toCharArray();
    char[] keystorePassword = restConfiguration.getKeyStorePassword().toCharArray();

    RestTemplate resultTemplate = new RestTemplateBuilder().build();
    try {
      // resolve key and trust store locations
      File keyStoreFile = ResourceUtils.getFile(keystore);
      File trustStoreFile = ResourceUtils.getFile(truststore);

      // load up the key and trust store
      SSLContext sslContext =
          SSLContextBuilder.create()
              .loadKeyMaterial(keyStoreFile, keystorePassword, keystorePassword)
              .loadTrustMaterial(trustStoreFile, truststorePassword)
              .build();

      // set the http client to use the loaded key and trust store
      HttpClient client = HttpClients.custom().setSSLContext(sslContext).build();
      ClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(client);

      // set the charset
      resultTemplate
          .getMessageConverters()
          .add(0, new StringHttpMessageConverter(StandardCharsets.UTF_8));
      resultTemplate.setRequestFactory(requestFactory);

    } catch (Exception ex) {
      // basic error handling if something goes wrong with the ssl context set up
      log.error("Couldn't set up client ssl context: " + ex.getMessage());
    }

    return resultTemplate;
  }
}
