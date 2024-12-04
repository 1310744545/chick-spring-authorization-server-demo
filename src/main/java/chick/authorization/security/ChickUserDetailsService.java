package chick.authorization.security;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import java.util.*;

//@Service
public class ChickUserDetailsService implements UserDetailsService {
    private final JdbcTemplate jdbcTemplate;

    public ChickUserDetailsService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 查询逻辑 通过用户名查询用户信息，按照自己的逻辑写
        String query = "SELECT username, password FROM users WHERE username = ?";
        ChickUserDetails chickUserDetails = jdbcTemplate.queryForObject(query, (rs, rowNum) -> {
            ChickUserDetails user = new ChickUserDetails();
            user.setUsername(rs.getString("username"));
            user.setPassword(rs.getString("password"));
            return user;
        }, username);
        if (ObjectUtils.isEmpty(chickUserDetails)){
            throw new UsernameNotFoundException(username + " not found");
        }

        String queryAuthority = "SELECT authority FROM authorities WHERE username = '" + username + "'";
        List<String> authorities = jdbcTemplate.query(queryAuthority, (rs, rowNum) -> rs.getString("authority"));
        Set<GrantedAuthority> simpleGrantedAuthorities = new HashSet<>();
        authorities.forEach(authority -> {
            SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(authority);
            simpleGrantedAuthorities.add(simpleGrantedAuthority);
        });
        chickUserDetails.setAuthorities(simpleGrantedAuthorities);
        return chickUserDetails;
    }
}
