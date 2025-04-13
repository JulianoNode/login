package com.JMR.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.JMR.domain.Afiliado;

public interface AfiliadoRepository extends JpaRepository<Afiliado, Long>{

	@Query("select a from Afiliado a where a.usuario.id = :id")
	Optional<Afiliado> findByUsuarioId(Long id);

	@Query("select a from Afiliado a where a.usuario.email like :email")
	Optional<Afiliado> findByUsuarioEmail(String email);


}
