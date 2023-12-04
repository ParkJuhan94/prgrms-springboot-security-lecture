package com.prgrms.devcourse.configures;

import static org.apache.commons.lang3.math.NumberUtils.toInt;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;

public class CustomWebSecurityExpressionRoot extends WebSecurityExpressionRoot {

    static final Pattern PATTERN = Pattern.compile("[0-9]+$");
    public CustomWebSecurityExpressionRoot(Authentication a, FilterInvocation fi) {
        super(a, fi);
    }

    public boolean isOddAmin() {
        User user = (User) getAuthentication().getPrincipal();
        String username = user.getUsername();
        Matcher matcher = PATTERN.matcher(username);

        if(matcher.find()){
            int number = toInt(matcher.group(), 0);
            return number % 2 == 1;
        }
        return false;
    }

}