package br.com.alura.forum.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import br.com.alura.forum.repository.UsuarioRepository;

/**
 * Classe para habilitar e configurar o controle de autenticação e autorização do projeto.
 * @author t736457
 *
 */
@EnableWebSecurity
@Configuration
@Profile(value = {"prod", "test"})
public class SecurityConfigurations extends WebSecurityConfigurerAdapter {

	@Autowired
	private AutenticacaoService autenticacaoService;
	
	@Autowired
	private TokenService tokenService;
	
	@Autowired
	private UsuarioRepository usuarioRepository;
	
	/**
	 * Para poder injetar o AuthenticationManager no controller
	 */
	@Override
	@Bean
	protected AuthenticationManager authenticationManager() throws Exception {
		return super.authenticationManager();
	}
	
	// Configurações de Autenticação
	/**
	 * Indica ao Spring Security qual o algoritmo de hashing de senha que utilizaremos na API, chamando o 
	 * método passwordEncoder()
	 */
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(autenticacaoService)
		.passwordEncoder(new BCryptPasswordEncoder()); // Geração do hash da senha usando o algoritmo BCrypt
		
	}
	
	// Configurações de Autorização
	/*
	 * Libera acesso aos endpoints da API.
	 * O método http.authorizeRequests().antMatchers().permitAll libera acesso a algum endpoint da API.
	 * O método anyRequest().authenticated() indica ao Spring Security para bloquear todos os endpoints que não foram
	 * liberados anteriormente com o método permitAll
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		.antMatchers(HttpMethod.GET, "/topicos").permitAll()
		.antMatchers(HttpMethod.GET, "/topicos/*").permitAll()
		.antMatchers(HttpMethod.POST, "/auth").permitAll()
		.antMatchers(HttpMethod.GET, "/actuator/**").permitAll()
		.antMatchers(HttpMethod.DELETE, "/topicos/*").hasRole("MODERADOR")
		.anyRequest().authenticated() // Qualquer outra requisição tem que estar autenticada
		.and().csrf().disable() // Desabilitando proteção CSRF
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Para configurar a autenticação stateless no Spring Security
		.and().addFilterBefore(new AutenticacaoViaTokenFilter(tokenService, usuarioRepository), UsernamePasswordAuthenticationFilter.class); // Para registrar o filtro no Spring
	}
	
//	// Configurações de recursos estáticos (js, css, imagens, etc)
//	@Override
//	public void configure(WebSecurity web) throws Exception {
////		web.ignoring().antMatchers("/**.html", "/v2/api-docs", "/webjars/**", "/configuration/**", "/swagger-resources/**", "/swagger-ui.html");
//        web.ignoring().antMatchers(
//        		"/**.html",
//        		"/v2/api-docs",
//        		"/webjars/**",
//                "/configuration/**",
//                "/swagger-resources/**",
//                "/configuration/security",
//                "**/swagger-ui/index.html"
//                );
//	}
	
	@Override
	public void configure(WebSecurity web) throws Exception {
	    web.ignoring()
	        .antMatchers("/**.html", "/v2/api-docs", "/webjars/**", "/configuration/**", "/swagger-resources/**");
	}
	
//	public static void main(String[] args) {
//		System.out.println(new BCryptPasswordEncoder().encode("123456")); // Gera o hash do 123456 no formato do BCrypt
//	}
	
}

