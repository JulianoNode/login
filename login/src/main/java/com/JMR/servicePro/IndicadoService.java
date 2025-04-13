package com.JMR.servicePro;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.data.domain.Sort;

import com.JMR.domainPro.Indicado;
import com.JMR.repository.PlataformaRepository;
import com.JMR.repositoryPro.IndicadoRepository;


@Service
public class IndicadoService {

	@Autowired
	private IndicadoRepository indicadoRepository;
	@Autowired
	private PlataformaRepository plataformaRepository;

	@Transactional(readOnly = false)
	public void salvar(Indicado indicado) {
		indicadoRepository.save(indicado);
	}
	
	@Transactional(readOnly = true)
	public void exibir(Indicado indicado, Model model) {
		model.addAttribute("listaPlataformas", this.plataformaRepository.findAll(Sort.by("titulo")));
		model.addAttribute("listaPlataformas", this.plataformaRepository.findAll(Sort.by("descricao")));
	}
	
	@Transactional(readOnly = true)
	public void editar(Indicado indicado, Long id, Model model) {		
		model.addAttribute("indicado", this.indicadoRepository.findById(id));	
		exibir(indicado, model);
	}

	@Transactional(readOnly = true)
	public byte[] image(Long idprod) {
		Indicado indicado = this.indicadoRepository.getReferenceById(idprod);
		return indicado.getImagem();
	}
	

}
