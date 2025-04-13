package com.JMR.repositoryPro;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.JpaRepository;

import com.JMR.domain.Plataforma;
import com.JMR.domainPro.Indicado;

public interface IndicadoRepository extends JpaRepository<Indicado, Long>{
	
	List<Indicado> findByNomeContainingIgnoreCase(String nomeIndicado, Sort sort);
	
	//Funções para o SELECT no salvar Informação
	Page<Indicado> findByPlataformaIsNull(List<Plataforma> plataformas, Pageable pageable);
	
	
}
