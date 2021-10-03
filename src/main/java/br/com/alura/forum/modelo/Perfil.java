package br.com.alura.forum.modelo;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import org.springframework.security.core.GrantedAuthority;

/**
 * Classe que representa o perfil de acesso do usuário.
 * @author t736457
 */
@Entity
public class Perfil implements GrantedAuthority {
	
	private static final long serialVersionUID = 1L;

	@Id @GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	
	private String nome;

	public Long getId() {
		return id;
	}

	public String getNome() {
		return nome;
	}

	@Override
	public String getAuthority() {
		return nome;
	}

}
