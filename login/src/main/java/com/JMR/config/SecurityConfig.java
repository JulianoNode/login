package com.JMR.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.JMR.domain.PerfilTipo;
import com.JMR.service.UsuarioService;

@Configuration
@EnableMethodSecurity
@EnableWebSecurity
public class SecurityConfig {

	private static final String ADMIN = PerfilTipo.ADMIN.getDesc();
	private static final String AFILIADO = PerfilTipo.AFILIADO.getDesc();

	// private static final String START = PerfilTipo.START.getDesc();

	@Bean
	SecurityFilterChain configure(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(authorize -> {
			configurarAcessosPublicos(authorize);
			configurarAcessosAfiliado(authorize);
			configurarAcessosAdmin(authorize);
			configurarAcessosEspecialidades(authorize);

			// Qualquer outra requisição precisa estar autenticada
			authorize.anyRequest().authenticated();
		}).formLogin().loginPage("/login").defaultSuccessUrl("/", true).failureUrl("/login-error").permitAll().and()
				.logout().logoutSuccessUrl("/").and().exceptionHandling().accessDeniedPage("/acesso-negado");

		return http.build();
	}

	private void configurarAcessosPublicos(
			AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authorize) {
		authorize.requestMatchers("/webjars/**", "/css/**", "/image/**", "/js/**").permitAll()
				.requestMatchers("/vendas/**").permitAll().requestMatchers("/", "/home").permitAll()
				.requestMatchers("/fragments/links-header/visitante.html").permitAll()

				.requestMatchers("/imagemIndicado/{idprod}").permitAll()
				.requestMatchers("/IndicadoScrollTopUser/ajax").permitAll()
				.requestMatchers("/Indicados").permitAll()
				.requestMatchers("/pesquisarIndicados").permitAll()
				.requestMatchers("/buscarIndicados").permitAll();
	}
	private void configurarAcessosAfiliado(
			AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authorize) {
		authorize.requestMatchers("/afiliados/dados", "/afiliados/salvar", "/afiliados/editar", "/salvarCategoria")
				.hasAnyAuthority(AFILIADO, ADMIN).requestMatchers("/afiliados/**").hasAuthority(AFILIADO);
	}
	private void configurarAcessosAdmin(
			AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authorize) {
		authorize.requestMatchers("/u/editar/senha", "/u/confirmar/senha").hasAnyAuthority(AFILIADO)
				.requestMatchers("/u/**").hasAuthority(ADMIN);
	}
	private void configurarAcessosEspecialidades(
			AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authorize) {
		authorize.requestMatchers("/especialidades/datatables/server/afiliado/*").hasAnyAuthority(AFILIADO, ADMIN)
				.requestMatchers("/especialidades/titulo").hasAnyAuthority(AFILIADO, ADMIN)
				.requestMatchers("/especialidades/**").hasAuthority(ADMIN);
	}
	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	@Bean
	AuthenticationManager authenticationManager(HttpSecurity http, PasswordEncoder passwordEncoder,
			UsuarioService userDetailsService) throws Exception {
		return http.getSharedObject(AuthenticationManagerBuilder.class).userDetailsService(userDetailsService)
				.passwordEncoder(passwordEncoder).and().build();
	}

}
