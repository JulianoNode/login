package com.JMR.web.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.JMR.domain.Afiliado;
import com.JMR.domain.Usuario;
import com.JMR.service.AfiliadoService;
import com.JMR.service.UsuarioService;

@Controller 
@RequestMapping("afiliados")
public class AfiliadoController {
	
	
	@Autowired
	private AfiliadoService service;	
	@Autowired
	private UsuarioService usuarioService;	
	
	// abrir pagina de dados pessoais de afiliados pelo AFILIADO
		@GetMapping({"/dados"})
		public String abrirPorAfiliado(Afiliado afiliado, ModelMap model, 
				@AuthenticationPrincipal User user) {
			
			if (afiliado.hasNotId()) {
				afiliado = service.buscarPorEmail(user.getUsername());
				model.addAttribute("afiliado", afiliado);
			}
			
			return "afiliado/cadastro";
		}
	
	// salvar afiliado
	@PostMapping({"/salvar"})
	public String salvar(Afiliado afiliado, RedirectAttributes attr, 
                @AuthenticationPrincipal User user) {
        // Recuperando dados do * AFILIADO *    
		if (afiliado.hasNotId() && afiliado.getUsuario().hasNotId()) {
			Usuario usuario = usuarioService.buscarPorEmail(user.getUsername());
			afiliado.setUsuario(usuario);
		}
	
                service.salvar(afiliado);
		attr.addFlashAttribute("sucesso", "Operação realizada com sucesso.");
		attr.addFlashAttribute("afiliado", afiliado);
		return "redirect:/afiliados/dados";
	}
	
	// editar afiliado
	@PostMapping({"/editar"})
	public String editar(Afiliado afiliado, RedirectAttributes attr) {
		service.editar(afiliado);
		attr.addFlashAttribute("sucesso", "Operação realizada com sucesso.");
		attr.addFlashAttribute("afiliado", afiliado);
		return "redirect:/afiliados/dados";		
	}
	
	// excluir especialidade
		@GetMapping({"/id/{idAfi}/excluir/especializacao/{idEsp}"})
		public String excluirEspecialidadePorAfiliado(@PathVariable("idAfi") Long idAfi, 
							 @PathVariable("idEsp") Long idEsp, RedirectAttributes attr) {
			
			service.excluirEspecialidadePorAfiliado(idAfi, idEsp);
			attr.addFlashAttribute("sucesso", "Especialidade do Afiliado removida com sucesso.");
			return "redirect:/afiliados/dados";	
			
		}

}
