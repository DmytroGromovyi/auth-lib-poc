package com.poc.authlib.autoconfiguration.condition;

import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

public class NotSecuredCondition extends SecuredCondition {

    @Override
    public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
        return ConditionOutcome.inverse(super.getMatchOutcome(context, metadata));
    }
}
