package com.JMR.domainPro;

import com.JMR.domain.AbstractEntity;
import com.JMR.domain.Plataforma;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;

/*
* Referencia os BYTES que suporta no @Lob
* 
* columnDefinition="TINYBLOB"
* 
* TINYBLOB : maximum length of 255 bytes BLOB : maximum length of 65,535 bytes
* MEDIUMBLOB : maximum length of 16,777,215 bytes LONGBLOB : maximum length of
* 4,294,967,295 bytes
*/
@SuppressWarnings("serial")
@Entity
@Table(name = "indicados")
public class Indicado extends AbstractEntity<Long> {

	@Column(name = "nome", nullable = false, length = 2000)
	private String nome;

	@Lob
	@Column(name = "imagem", columnDefinition = "MEDIUMBLOB")
	private byte[] imagem;

	@NotNull(message = "Link deve ser preenchido")
	@Column(name = "link", nullable = false, unique = true)
	private String link;

	// ------------------- Muitos para Um Informações ------------------------------
	@ManyToOne
	@NotNull(message = "Plataforma deve ser selecionada")
	private Plataforma plataforma;

	// ------------------- Muitos para Um SQL Get e Set ---------------------

	public String getNome() {
		return nome;
	}

	public void setNome(String nome) {
		this.nome = nome;
	}

	public byte[] getImagem() {
		return imagem;
	}

	public void setImagem(byte[] imagem) {
		this.imagem = imagem;
	}

	public String getLink() {
		return link;
	}

	public void setLink(String link) {
		this.link = link;
	}

	public Plataforma getPlataforma() {
		return plataforma;
	}

	public void setPlataforma(Plataforma plataforma) {
		this.plataforma = plataforma;
	}
	

}