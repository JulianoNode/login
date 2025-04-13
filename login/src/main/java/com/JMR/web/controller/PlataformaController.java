package com.JMR.web.controller;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.JMR.domain.Plataforma;
import com.JMR.service.PlataformaService;


@Controller
@RequestMapping("plataformas")
public class PlataformaController {
	
	@Autowired
	private PlataformaService service;

	@GetMapping({"", "/"})
	public String abrir(Plataforma plataforma) {

		return "plataforma/plataformaCad";
	}
	
	@PostMapping("/salvar")
	public String salvar(Plataforma plataforma, RedirectAttributes attr) {
		try {
		service.salvar(plataforma);
		attr.addFlashAttribute("sucesso", "Operação realizada com sucesso!");
		} catch (Exception e) {
	            attr.addFlashAttribute("aviso", "ATENÇÂO! Operação não realizada! Essa CATEGORIA já está cadastrada!");
	            return "redirect:/plataformas";
	        }
		
		return "redirect:/plataformas";
	}
	
	@GetMapping("/datatables/server")
	public ResponseEntity<?> getPlataformas(HttpServletRequest request) {

		return ResponseEntity.ok(service.buscarPlataformas(request));
	}
	
	@GetMapping("/editar/{id}")
	public String preEditar(@PathVariable("id") Long id, ModelMap model) {
		model.addAttribute("plataforma", service.buscarPorId(id));
		return "plataforma/plataformaCad";
	}
	
	@GetMapping("/excluir/{id}")
	public String abrir(@PathVariable("id") Long id, RedirectAttributes attr) {
		service.remover(id);
		attr.addFlashAttribute("sucesso", "Operação realizada com sucesso.");
		return "redirect:/plataformas";
	}
}
