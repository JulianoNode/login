package com.JMR.domain;

import jakarta.persistence.*;

@SuppressWarnings("serial")
@Entity
@Table(name = "plataformas", indexes = {@Index(name = "idx_plataforma_plataforma", columnList = "plataforma")})
public class Plataforma extends AbstractEntity<Long> {
	
	@Column(name = "plataforma", unique = true, nullable = false, length = 50)
	private String titulo;
	
	@Column(name = "descricao", columnDefinition = "TEXT")
	private String descricao;
		
	public String getTitulo() {
		return titulo;
	}

	public void setTitulo(String titulo) {
		this.titulo = titulo;
	}	

	public String getDescricao() {
		return descricao;
	}

	public void setDescricao(String descricao) {
		this.descricao = descricao;
	}
}