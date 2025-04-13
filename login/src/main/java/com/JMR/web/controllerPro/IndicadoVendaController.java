package com.JMR.web.controllerPro;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.JMR.domainPro.Indicado;
import com.JMR.repositoryPro.IndicadoRepository;

@Controller
public class IndicadoVendaController {
	
	@Autowired
	private IndicadoRepository indicadoRepository;

	// ===== LISTAR OFERTAS =====
	@GetMapping("/Indicados")
	public String exibirIndicados(Model model) {
		Sort sort = Sort.by(Sort.Direction.ASC, "nome");
		PageRequest page = PageRequest.of(0, 40, sort);// Quantidades de cards a mostrar na pagina
		model.addAttribute("listaIndicados", this.indicadoRepository.findAll(page));
		return "vendas/userIndicado/indicado-search";
	}
	
	@Transactional(readOnly = true)
	@GetMapping("/IndicadoScrollTopUser/ajax")
	public String listarCards(@RequestParam(name = "page", defaultValue = "1") int page, Model model) {
		Sort sort = Sort.by(Sort.Direction.ASC, "nome");
		PageRequest pageRequest = PageRequest.of(page, 40, sort);// Quantidades de cards a mostrar na pagina

		model.addAttribute("listaIndicados", this.indicadoRepository.findAll(pageRequest));

		return "vendas/userIndicado/indicado-list-card";
	}

	// ===== Pesquisar OFERTAS =====

	@GetMapping("/pesquisarIndicados")
	public String pesquisarIndicados(@RequestParam("nome")String nomeIndicado, ModelMap model) {

		List<Indicado> resultado = this.indicadoRepository
				.findByNomeContainingIgnoreCase(nomeIndicado, Sort.by("nome"));
		model.addAttribute("listaIndicados", resultado);
		return "vendas/userIndicado/indicado-search";
	}

}