package com.wzp.module.security.config;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.DigestUtils;

import java.nio.charset.StandardCharsets;

public class MyPasswordEncoder implements PasswordEncoder {

    private final static String salt = "3MzPA9U1yxnDtR8ww9e9Z5hG3UhqgpdO";

    /**
     * Encode the raw password. Generally, a good encoding algorithm applies a SHA-1 or
     * greater hash combined with an 8-byte or greater randomly generated salt.
     *
     * @param rawPassword
     */
    @Override
    public String encode(CharSequence rawPassword) {
        return DigestUtils.md5DigestAsHex((rawPassword + salt).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Verify the encoded password obtained from storage matches the submitted raw
     * password after it too is encoded. Returns true if the passwords match, false if
     * they do not. The stored password itself is never decoded.
     *
     * @param rawPassword     the raw password to encode and match
     * @param encodedPassword the encoded password from storage to compare with
     * @return true if the raw password, after encoding, matches the encoded password from
     * storage
     */
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return encode(rawPassword).equals(encodedPassword);
    }

    private void test() {

    }
}
