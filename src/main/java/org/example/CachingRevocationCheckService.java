package org.example;

import ch.qos.logback.core.util.TimeUtil;
import org.springframework.scheduling.annotation.Scheduled;

import java.util.Set;
import java.util.concurrent.TimeUnit;

public class CachingRevocationCheckService implements RevocationChekServace{
    volatile Set<String> revokedIds = Set.of();

    @Override
    public boolean isRevoked(String tokenId){ return revokedIds.contains(tokenId);}

    @Scheduled(fixedRate = 5,timeUnit = TimeUnit.SECONDS)
    void updateRevokedList(){
        revokedIds = Set.of(
                "123"
        );
    }
}
