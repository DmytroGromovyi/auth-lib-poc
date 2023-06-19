package com.poc.authlib.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Data
@Validated
@ConfigurationProperties(prefix = "auth.service")
public class AuthServiceProperties {
    @NotBlank
    private String endpoint;
    @NotBlank
    private String getUserPath;
    @Min(5000)
    @NotNull
    private Integer timeout;
    @NotBlank
    private String errorMessage;
}
