package com.JMR.web.controller;

import java.util.Arrays;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.JMR.domain.Afiliado;
import com.JMR.domain.Perfil;
import com.JMR.domain.PerfilTipo;
import com.JMR.domain.Usuario;
import com.JMR.service.AfiliadoService;
import com.JMR.service.UsuarioService;

@Controller
@RequestMapping("u")
public class UsuarioController {

	@Autowired
	private UsuarioService service;

	@Autowired
	private AfiliadoService afiliadoService;

	// abrir cadastro de usuarios (afiliado/admin)
	@GetMapping("/novo/cadastro/usuario")
	public String cadastroPorAdminParaAdminAfiliado(Usuario usuario) {

		return "usuario/cadastro";
	}

	// abrir lista de usuarios
	@GetMapping("/lista")
	public String listarUsuarios() {

		return "usuario/lista";
	}

	// listar usuarios na datatables
	@GetMapping("/datatables/server/usuarios")
	public ResponseEntity<?> listarUsuariosDatatables(HttpServletRequest request) {

		return ResponseEntity.ok(service.buscarTodos(request));
	}

	// salvar cadastro de usuarios por administrador
	@PostMapping("/cadastro/salvar")
	public String salvarUsuarios(Usuario usuario, RedirectAttributes attr) {
		List<Perfil> perfis = usuario.getPerfis();
		if (perfis.size() > 2 || perfis.containsAll(Arrays.asList(new Perfil(1L), new Perfil(3L)))
				|| perfis.containsAll(Arrays.asList(new Perfil(2L), new Perfil(3L)))) {
			attr.addFlashAttribute("falha", "Afiliado_Start não pode ser Admin e/ou Afilido Master.");
			attr.addFlashAttribute("usuario", usuario);
		} else {
			try {
				service.salvarUsuario(usuario);
				attr.addFlashAttribute("sucesso", "Operação de CADASTRO realizada com sucesso!");
			} catch (DataIntegrityViolationException ex) {
				attr.addFlashAttribute("aviso", "ATENÇÂO! Operação não realizada! Essa EMAIL já está cadastrada!");
			}
		}
		return "redirect:/u/novo/cadastro/usuario";
	}

	// Pre-Edicao de credenciais de usuarios
	@GetMapping("/editar/credenciais/usuario/{id}")
	public ModelAndView preEditarCredenciais(@PathVariable("id") Long id) {

		return new ModelAndView("usuario/cadastro", "usuario", service.buscarPorId(id));
	}

	// pre edicao de cadastro de usuarios por Perfis
	@GetMapping("/editar/dados/usuario/{id}/perfis/{perfis}")
	public ModelAndView preEditarCadastroDadosPessoais(@PathVariable("id") Long usuarioId,
			@PathVariable("perfis") Long[] perfisId) {

		Usuario us = service.buscarPorIdEPerfis(usuarioId, perfisId);

		if (us.getPerfis().contains(new Perfil(PerfilTipo.ADMIN.getCod()))
				&& !us.getPerfis().contains(new Perfil(PerfilTipo.AFILIADO.getCod()))) {

			return new ModelAndView("usuario/cadastro", "usuario", us);

		} else if (us.getPerfis().contains(new Perfil(PerfilTipo.AFILIADO.getCod()))) {

			Afiliado afiliado = afiliadoService.buscarPorUsuarioId(usuarioId);
			return afiliado.hasNotId()
					? new ModelAndView("afiliado/cadastro", "afiliado", new Afiliado(new Usuario(usuarioId)))
					: new ModelAndView("afiliado/cadastro", "afiliado", afiliado);

		} else if (us.getPerfis().contains(new Perfil(PerfilTipo.START.getCod()))) {
			ModelAndView model = new ModelAndView("error");
			model.addObject("status", 403);
			model.addObject("error", "Área Restrita");
			model.addObject("message", "Os dados de Afiliado Start são restritos a ele.");
			return model;
		}

		return new ModelAndView("redirect:/u/lista");

	}
	
	// Editar a senha do usuario
    @GetMapping("/editar/senha")
    public String abrirEditarSenha() {
    	
    	return "usuario/editar-senha";
    }
    // Redefinir senha de usuario
    @PostMapping("/confirmar/senha")
    public String editarSenha(@RequestParam("senha1") String s1, @RequestParam("senha2") String s2, 
    						  @RequestParam("senha3") String s3, @AuthenticationPrincipal User user,
    						  RedirectAttributes attr) {
    	
    	if (!s1.equals(s2)) {
    		attr.addFlashAttribute("falha", "Senhas não conferem, tente novamente");
    		return "redirect:/u/editar/senha";
    	}
    	
    	Usuario u = service.buscarPorEmail(user.getUsername());
    	if(!UsuarioService.isSenhaCorreta(s3, u.getSenha())) {
    		attr.addFlashAttribute("falha", "Senha atual não confere, tente novamente");
    		return "redirect:/u/editar/senha";
    	}
    		
    	service.alterarSenha(u, s1);
    	attr.addFlashAttribute("sucesso", "Senha alterada com sucesso.");
    	return "redirect:/u/editar/senha";
    }
	
	
	

}
