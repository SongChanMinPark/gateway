package com.camp.gateway.filter;

import io.jsonwebtoken.Jwts;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    private String secretKey = "TESTSECRET";


    private Environment env;

    public AuthorizationHeaderFilter(Environment env) {
        super(Config.class);
    }

    @Setter
    public static class Config {
        private String role;
    }

    @Override
    public GatewayFilter apply(Config config) {
        System.out.println("Auth Filter - In");
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            log.info("============= Auth GatewayFilter ============= ");
            log.info("Logging PRE Start : request id = {}", request.getId());
            log.info("Logging PRE Start : request uri = {}", request.getURI());
            /*
            MultiValueMap<String, HttpCookie> cookies = request.getCookies(); // request.getCookies();

            HttpCookie cookie = cookies.getFirst("token");

            if(cookie == null){
                log.info("Cookie is not exists  :::::::: ");
                return onError(exchange, "Cookie is not exists", HttpStatus.UNAUTHORIZED);
            }

            String jwt =cookie.getValue();
            log.info("jwt  :::::::: {}", jwt);

            if (!isJwtValid(jwt)) {
                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }
            */
            return chain.filter(exchange);
        };
    }


    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        //log.error(err);
        return response.setComplete();
    }


    private boolean isJwtValid(String jwt) {
        boolean returnValue = true;

        String subject = null;

        try {
            subject = Jwts.parser().setSigningKey(secretKey.getBytes())
                    .parseClaimsJws(jwt).getBody()
                    .getSubject();

            log.info("subject::: {}", subject);

        } catch (Exception ex) {
            log.info(ex.getMessage());
            returnValue = false;
        }

        if (subject == null || subject.isEmpty()) {
            returnValue = false;
        }

        log.info("returnValue ::: {}", returnValue);

        return returnValue;
    }


}
