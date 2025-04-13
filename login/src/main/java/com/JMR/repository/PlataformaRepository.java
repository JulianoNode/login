package com.JMR.repository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.JMR.domain.Plataforma;

public interface PlataformaRepository extends JpaRepository<Plataforma, Long>{

	@Query("select e from Plataforma e where e.titulo like :search%")
	Page<Plataforma> findAllByTitulo(String search, Pageable pageable);

}

