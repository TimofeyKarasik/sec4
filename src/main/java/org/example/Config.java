package org.example;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableScheduling
@Configuration
public class Config {
    @Bean
    RevocationChekServace revocationChekServace(){
        return new CachingRevocationCheckService();
    }
}
