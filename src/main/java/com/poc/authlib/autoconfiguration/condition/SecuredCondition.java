package com.poc.authlib.autoconfiguration.condition;

import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;

import java.util.Optional;

public class SecuredCondition extends SpringBootCondition {

    private static final String SECURITY_SWITCH_PROPERTY_NAME = "app.enable.security";
    private static final boolean MATCH_IF_ABSENT = Boolean.TRUE;

    @Override
    public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
        if (isSecurityExplicitlyTurnedOn(context.getEnvironment())) {
            return ConditionOutcome.match("Security is enabled.");
        }
        return ConditionOutcome.noMatch("Security is disabled.");
    }

    private Boolean isSecurityExplicitlyTurnedOn(Environment environment) {
        return Optional.ofNullable(environment.getProperty(SECURITY_SWITCH_PROPERTY_NAME, Boolean.class))
                .orElse(MATCH_IF_ABSENT);
    }

}
