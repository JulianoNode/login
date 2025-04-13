package com.JMR.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.JMR.domain.Afiliado;
import com.JMR.repository.AfiliadoRepository;

@Service
public class AfiliadoService {

	@Autowired
	private AfiliadoRepository repository;

	// Buscar Afiliado
	@Transactional(readOnly = true)
	public Afiliado buscarPorUsuarioId(Long id) {

		return repository.findByUsuarioId(id).orElse(new Afiliado());
	}

	// Salvar Afiliado
	@Transactional(readOnly = false)
	public void salvar(Afiliado afiliado) {

		repository.save(afiliado);
	}

	// Editar Afiliado
	@Transactional(readOnly = false)
	public void editar(Afiliado afiliado) {
		Afiliado m2 = repository.findById(afiliado.getId()).get();

		m2.setNome(afiliado.getNome());

		if (!afiliado.getEspecialidades().isEmpty()) {
			m2.getEspecialidades().addAll(afiliado.getEspecialidades());
		}
	}

	// Buscar dados por E-mail de * AFILAIFO *
	@Transactional(readOnly = true)
	public Afiliado buscarPorEmail(String email) {

		return repository.findByUsuarioEmail(email).orElse(new Afiliado());
	}

	// Excluir uma especialidade do afiliado
	@Transactional(readOnly = false)
	public void excluirEspecialidadePorAfiliado(Long idAfi, Long idEsp) {
		
		Afiliado afiliado = repository.findById(idAfi).get();
		afiliado.getEspecialidades().removeIf(e -> e.getId().equals(idEsp));
		
	}

}
