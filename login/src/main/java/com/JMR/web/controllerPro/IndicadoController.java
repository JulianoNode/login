package com.JMR.web.controllerPro;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.JMR.domainPro.Indicado;
import com.JMR.repositoryPro.IndicadoRepository;
import com.JMR.servicePro.IndicadoService;

import jakarta.validation.Valid;

@Controller
public class IndicadoController {
	@Autowired
	private IndicadoService serviceI;
	@Autowired
	private IndicadoRepository indicadoRepository;

	// ===== EXIBIR O FORMULARIO DE CADASTRO DE OFERTAS =====
	
	@GetMapping("/exibirFormIndicado")
	public String exibirForm(Indicado indicado, Model model) {
		serviceI.exibir(indicado, model);
		return "indicado/indicado-form";
	}

	@PostMapping("/salvarIndicado")
	public String salvarIndicado(@Valid Indicado indicado, RedirectAttributes attr, BindingResult result, Model model,
			@RequestParam("fileIndicado") MultipartFile file) {
		if (result.hasErrors()) {
			return exibirForm(indicado, model);
		}
		try {
			indicado.setImagem(file.getBytes());
			serviceI.salvar(indicado);
			attr.addFlashAttribute("sucesso", "Operação realizada com sucesso!");
			return "redirect:/exibirFormIndicado";
		} catch (Exception e) {
			attr.addFlashAttribute("aviso", "ATENÇÂO! Operação não realizada, URL do Site já cadastrado!");
			return "redirect:/exibirFormIndicado";
		}

	}
	// ===== LISTAR OFERTAS =====

	@Transactional(readOnly = true)
	@GetMapping("/listarIndicados")
	public String exibirLista(Model model) {
		Sort sort = Sort.by(Sort.Direction.ASC, "nome");
		PageRequest page = PageRequest.of(0, 40, sort);// Quantidades de cards a mostrar na pagina
		model.addAttribute("listaIndicados", this.indicadoRepository.findAll(page));
		return "indicado/indicadoListSearch";

	}

	@Transactional(readOnly = true)
	@GetMapping("/IndicadoScrollTopSyst/ajax")
	public String listarCards(@RequestParam(name = "page", defaultValue = "1") int page, Model model) {
		Sort sort = Sort.by(Sort.Direction.ASC, "nome");
		PageRequest pageRequest = PageRequest.of(page, 40, sort);// Quantidades de cards a mostrar na pagina

		model.addAttribute("listaIndicados", this.indicadoRepository.findAll(pageRequest));
		return "indicado/indicado-list-card";
	}

	@GetMapping("/imagemIndicado/{idprod}")
	@ResponseBody
	public byte[] exibirImagen(@PathVariable("idprod") Long idprod) {

		return serviceI.image(idprod);

	}

	// ===== EDITAR OFERTAS =====

	@GetMapping("/editarIndicado")
	public String editarIndicado(Indicado indicado,Long id, Model model) {

		serviceI.editar(indicado, id, model);
		return "indicado/indicado-form";
	}

	// ===== Pesquisar OFERTAS =====

	@PostMapping("/buscarIndicados")
	public String buscarIndicados(String nomeIndicado, Model model) {

		List<Indicado> resultado = this.indicadoRepository.findByNomeContainingIgnoreCase(nomeIndicado,
				Sort.by("nome"));
		model.addAttribute("listaIndicados", resultado);
		return "indicado/indicadoListSearch";
	}
}
