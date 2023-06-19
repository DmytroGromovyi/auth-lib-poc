package com.poc.authlib.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;

@Validated
@Data
@ConfigurationProperties(prefix = "security.urls")
public class OpenUrlProperties {
    private List<String> openUrls;
}
