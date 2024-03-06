package com.nowherelearn.clientservice.api;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;
import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@Controller
public class ClientController {
    private final WebClient webClient;
    private final String postServiceBaseUri;

    public ClientController(WebClient webClient) {
        this.webClient = webClient;
        this.postServiceBaseUri = "http://localhost/post-service";
    }

    @GetMapping(value = "/authorize", params = "grant_type=authorization_code")
    public String authorizationCodeGrant(Model model,
                                         @RegisteredOAuth2AuthorizedClient("nowhere-client-authorization-code")
                                         OAuth2AuthorizedClient authorizedClient) {

        String posts = this.webClient
                .get()
                .uri(this.postServiceBaseUri +"/posts")
                .attributes(oauth2AuthorizedClient(authorizedClient))
                        .retrieve().bodyToMono(String.class).block();
        model.addAttribute("messages", posts);

        return "index";
    }

    // '/authorized' is the registered 'redirect_uri' for authorization_code
    @GetMapping(value = "/authorized", params = OAuth2ParameterNames.ERROR)
    public String authorizationFailed(Model model, HttpServletRequest request) {
        String errorCode = request.getParameter(OAuth2ParameterNames.ERROR);
        if (StringUtils.hasText(errorCode)) {
            model.addAttribute("error",
                    new OAuth2Error(
                            errorCode,
                            request.getParameter(OAuth2ParameterNames.ERROR_DESCRIPTION),
                            request.getParameter(OAuth2ParameterNames.ERROR_URI))
            );
        }

        return "index";
    }

    @GetMapping(value = "/authorize", params = "grant_type=client_credentials")
    public String clientCredentialsGrant(Model model) {

        String clientName = this.webClient
                .get()
                .uri(this.postServiceBaseUri +"/test")
                .attributes(clientRegistrationId("nowhere-client-client-credentials"))
                .retrieve()
                .bodyToMono(String.class)
                .block();
        model.addAttribute("messages", clientName);

        return "index";
    }

    @ExceptionHandler(WebClientResponseException.class)
    public String handleError(Model model, WebClientResponseException ex) {
        model.addAttribute("error", ex.getMessage());
        return "index";
    }

}
