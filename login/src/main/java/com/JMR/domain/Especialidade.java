package com.JMR.domain;

import java.util.List;

import jakarta.persistence.*;



@SuppressWarnings("serial")
@Entity
@Table(name = "especialidades", indexes = {@Index(name = "idx_especialidade_titulo", columnList = "titulo")})
public class Especialidade extends AbstractEntity <Long>{
	
	@Column(name = "titulo", unique = true, nullable = false, length = 50)
	private String titulo;
	
	@Column(name = "descricao", columnDefinition = "TEXT")
	private String descricao;
	
	@ManyToMany
	@JoinTable(
			name = "afiliados_tem_especialidades",
			joinColumns = @JoinColumn(name = "id_especialidade", referencedColumnName = "id"),
			inverseJoinColumns = @JoinColumn(name = "id_afiliado", referencedColumnName = "id")
    )
	private List<Afiliado> afiliados;	

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

	public List<Afiliado> getAfiliados() {
		return afiliados;
	}

	public void setAfiliado(List<Afiliado> afiliados) {
		this.afiliados = afiliados;
	}
}
