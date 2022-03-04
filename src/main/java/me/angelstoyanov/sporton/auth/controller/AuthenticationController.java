package me.angelstoyanov.sporton.auth.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.Map;

@RestController
public class AuthenticationController {

    @Autowired
    ResourceServerTokenServices resourceServerTokenServices;

    @Value("${sporton.azb2c.user.management.svc.url}")
    private String resourceServerUri;

    @Value("${sporton.azb2c.user.id.header}")
    private String userIdHeaderName;

    @Value("${sporton.azb2c.user.role.header}")
    private String userRoleHeaderName;

    @Value("${sporton.azb2c.user.role.unverified}")
    private String userRoleUnverified;


    @GetMapping("/authenticate")
    public ResponseEntity<String> test(@RequestHeader("Authorization") String authorization) throws JsonProcessingException {

        OAuth2AccessToken token = resourceServerTokenServices
                .readAccessToken(StringUtils.substringAfter(authorization, "Bearer "));

        Map<String, Object> payload = getPayload(token);
        String userId = payload.get("oid").toString();

        return ResponseEntity
                .status(200)
                .header(userIdHeaderName, userId)
                .header(userRoleHeaderName, getUserRole(userId))
                .body(null);

    }

    private Map<String, Object> getPayload(OAuth2AccessToken accessToken) throws JsonProcessingException {
        Base64.Decoder decoder = Base64.getUrlDecoder();
        String[] chunks = accessToken.getValue().split("\\.");
        String payload = new String(decoder.decode(chunks[1]));
        return new ObjectMapper().readValue(payload, new TypeReference<>() {});
    }

    private String getUserRole(String userId) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<Map<String, Object>> httpEntity = new HttpEntity<>(null, headers);
        ParameterizedTypeReference<Map<String, Object>> responseType =
                new ParameterizedTypeReference<>() {
                };
        try {
            ResponseEntity<Map<String, Object>> response = restTemplate
                    .exchange(resourceServerUri + "/user/" + userId, HttpMethod.GET, httpEntity, responseType);

            if (response.getStatusCode() == HttpStatus.OK) {
                return response.getBody().getOrDefault("role", userRoleUnverified).toString();
            } else {
                return userRoleUnverified;
            }
        } catch (HttpClientErrorException e) {
            return userRoleUnverified;
        }
    }
}
