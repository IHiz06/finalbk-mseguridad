package com.cod.apigateway.filter;

import com.netflix.appinfo.InstanceInfo;
import com.netflix.discovery.EurekaClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Configuration
public class GlobalFilterConfiguration {

    @Component
    public class AuthenticationFilter implements GlobalFilter, Ordered {

        // Inyección del WebClient.Builder (se mantiene por si es necesario en el futuro)
        @Autowired
        private WebClient.Builder webClientBuilder;

        // Constantes y paths excluidos
        private final AntPathMatcher antPathMatcher = new AntPathMatcher();
        private static final List<String> EXCLUDE_PATHS = List.of(
                "/api/auth/v1/**"
        );

        @Override
        public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
            String path = exchange.getRequest().getURI().getPath();

            // Excluir paths configurados
            if (isExcludePath(path)) {
                return chain.filter(exchange);
            }

            // Obtener token del header
            String token = exchange.getRequest().getHeaders().getFirst("validate");

            if (token == null || token.isEmpty()) {
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }

            return chain.filter(exchange);
        }

        private boolean isExcludePath(String path) {
            return EXCLUDE_PATHS.stream().anyMatch(pattern -> antPathMatcher.match(pattern, path));
        }

        @Override
        public int getOrder() {
            return 0;
        }
    }
}

